"""Trusted bootstrap. Never call directly with a real repository as the root."""
import ctypes
import errno
import json
import os
import resource
import sys
import traceback


def must_zero(value, what):
    if value != 0:
        raise RuntimeError(f"{what}: errno={ctypes.get_errno()}")


def main():
    root, ready_fd, result_fd = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
    # Both library handles are loaded before chroot; no loader search path or
    # provider environment survives into untrusted code.
    libc = ctypes.CDLL(None, use_errno=True)
    seccomp = ctypes.CDLL("libseccomp.so.2", use_errno=True)
    libc.prctl.restype = ctypes.c_int
    request = json.loads(open(root + "/request.json", encoding="utf-8").read())
    limits = request["limits"]
    namespace_inodes = {kind: os.readlink("/proc/self/ns/" + kind) for kind in ("user", "pid", "net")}
    if os.getpid() != 1 or os.getuid() != 0:
        raise RuntimeError("Required user/PID namespaces were not entered")
    os.chroot(root)
    os.chdir("/work")
    stdlib_path = "/usr/lib/python%d.%d" % sys.version_info[:2]
    sys.path[:] = [stdlib_path, stdlib_path + "/lib-dynload", "/packages", "/work"]
    sys.argv[:] = ["skill.py"]
    os.environ.clear()
    os.environ.update({"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "TMPDIR": "/tmp", "LANG": "C.UTF-8"})
    for kind, value in ((resource.RLIMIT_CORE, 0), (resource.RLIMIT_CPU, limits["cpu_seconds"]),
                        (resource.RLIMIT_AS, limits["memory_bytes"]),
                        (resource.RLIMIT_FSIZE, limits["file_bytes"]),
                        (resource.RLIMIT_NOFILE, 64)):
        resource.setrlimit(kind, (value, value))
    # Drop supplementary groups before capabilities. map-root-user marks
    # setgroups denied on some kernels, which is safe because DAC capabilities
    # are removed and the chroot contains no host-owned data.
    try:
        os.setgroups([])
    except PermissionError:
        pass
    for capability in range(64):
        result = libc.prctl(24, capability, 0, 0, 0)  # PR_CAPBSET_DROP
        if result != 0 and ctypes.get_errno() != errno.EINVAL:
            raise RuntimeError("Cannot drop capability bounding set")
    must_zero(libc.prctl(38, 1, 0, 0, 0), "PR_SET_NO_NEW_PRIVS")

    class CapHeader(ctypes.Structure):
        _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]

    class CapData(ctypes.Structure):
        _fields_ = [("effective", ctypes.c_uint32), ("permitted", ctypes.c_uint32), ("inheritable", ctypes.c_uint32)]

    header = CapHeader(0x20080522, 0)
    caps = (CapData * 2)()
    must_zero(libc.capset(ctypes.byref(header), caps), "capset")
    must_zero(libc.capget(ctypes.byref(header), caps), "capget")
    if any(c.effective or c.permitted or c.inheritable for c in caps):
        raise RuntimeError("Capabilities remain")
    seccomp.seccomp_init.argtypes = [ctypes.c_uint32]
    seccomp.seccomp_init.restype = ctypes.c_void_p
    seccomp.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    seccomp.seccomp_syscall_resolve_name.restype = ctypes.c_int
    seccomp.seccomp_rule_add.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint]
    seccomp.seccomp_load.argtypes = [ctypes.c_void_p]
    seccomp.seccomp_release.argtypes = [ctypes.c_void_p]
    # Default EPERM; exec, fork/clone, namespace/mount, credentials, ptrace,
    # kernel keyrings, io_uring, bpf and file-permission changes stay denied.
    context = seccomp.seccomp_init(0x00050000 | errno.EPERM)
    if not context:
        raise RuntimeError("seccomp_init failed")
    allowed = """read write readv writev pread64 pwrite64 close close_range
        open openat access faccessat faccessat2 stat lstat fstat newfstatat statx
        lseek getdents getdents64 readlink readlinkat chdir getcwd
        unlink unlinkat rename renameat renameat2 mkdir mkdirat rmdir
        symlink symlinkat link linkat truncate ftruncate fsync fdatasync
        fcntl dup dup2 dup3 pipe pipe2 poll ppoll select pselect6
        mmap mprotect munmap mremap madvise brk futex
        rt_sigaction rt_sigprocmask rt_sigreturn sigaltstack
        getpid getppid gettid getuid geteuid getgid getegid getgroups
        clock_gettime clock_nanosleep nanosleep gettimeofday time getrandom
        uname sysinfo getrlimit getrusage sched_yield sched_getaffinity
        socket socketpair connect bind listen accept accept4 shutdown
        sendto recvfrom sendmsg recvmsg getsockname getpeername
        getsockopt setsockopt epoll_create epoll_create1 epoll_ctl epoll_wait epoll_pwait
        umask utime utimes utimensat exit exit_group""".split()
    for name in allowed:
        number = seccomp.seccomp_syscall_resolve_name(name.encode())
        if number >= 0:
            must_zero(seccomp.seccomp_rule_add(context, 0x7FFF0000, number, 0), "seccomp rule " + name)
    must_zero(seccomp.seccomp_load(context), "seccomp_load")
    seccomp.seccomp_release(context)
    ready = {"ready": True, "profile": "user-net-pid-chroot-seccomp-v1", "pid": os.getpid(),
             "namespace_inodes": namespace_inodes, "capabilities": 0,
             "no_new_privs": True, "seccomp": "syscall_allowlist",
             "network": "empty_network_namespace", "host_mounts": [],
             "processes": "fork_clone_exec_denied", "cwd": "/work"}
    os.write(ready_fd, json.dumps(ready).encode())
    os.close(ready_fd)  # Untrusted code cannot rewrite the readiness attestation.
    namespace = {"__name__": "__skill__", "__file__": "/work/skill.py"}
    result = {}
    try:
        exec(compile(request["code"], "/work/skill.py", "exec"), namespace)
        value = None
        if request["callable_name"] is not None:
            value = namespace[request["callable_name"]](*request["args"], **request["kwargs"])
        # Serialize promptly. Treat custom objects as repr output, not evidence.
        result = {"return_value": value}
        encoded = json.dumps(result, ensure_ascii=False, default=repr).encode()
    except BaseException as error:
        encoded = json.dumps({"execution_error": type(error).__name__ + ": " + str(error)}, ensure_ascii=False).encode()
        traceback.print_exc(limit=8)
    os.write(result_fd, encoded)
    os.close(result_fd)


if __name__ == "__main__":
    main()
