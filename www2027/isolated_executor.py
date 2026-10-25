"""Small Linux-only executor for untrusted Python skills.

The supervisor never imports skill code. A clean-environment process enters new
user, network and PID namespaces, chroots into a disposable root, drops every
capability and applies an allowlist seccomp filter before compiling the skill.
Only explicitly supplied fixture files are copied in. Results returned by code
are untrusted; filesystem observations are made by the outside supervisor.

Requires /usr/bin/python3, unshare, ldd, and libseccomp.so.2. This is an OS
containment boundary, not a defense against vulnerabilities in the host kernel.
Only pure-Python PyYAML is supplied in addition to the standard library. Child
processes and threads are deliberately unsupported. Storage is polled and may
briefly exceed the configured threshold before the process is terminated.
"""

from __future__ import annotations

import dataclasses
import base64
import hashlib
import json
import math
import os
from pathlib import Path
import selectors
import shutil
import signal
import stat
import subprocess
import tempfile
import time
from typing import Any


@dataclasses.dataclass(frozen=True)
class SandboxLimits:
    wall_seconds: float = 5.0
    cpu_seconds: int = 2
    memory_bytes: int = 256 * 1024 * 1024
    file_bytes: int = 1024 * 1024
    output_bytes: int = 128 * 1024
    fixture_bytes: int = 8 * 1024 * 1024
    disk_bytes: int = 16 * 1024 * 1024
    files: int = 256
    capture_bytes: int = 64 * 1024

    def __post_init__(self):
        if any(isinstance(value, bool) or not isinstance(value, (float, int))
               or not math.isfinite(value) or value <= 0
               for value in dataclasses.asdict(self).values()):
            raise ValueError("All sandbox limits must be positive")
        if any(not isinstance(value, int) for key, value in dataclasses.asdict(self).items()
               if key != "wall_seconds"):
            raise ValueError("All limits except wall_seconds must be integers")


class SandboxUnavailable(RuntimeError):
    """Containment could not be established; no untrusted code was executed."""


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _snapshot(directory: Path, limits: SandboxLimits, capture: bool = True):
    """Never follow symlinks or open special files supplied by the sandbox."""
    records, total_bytes, total_files = {}, 0, 0
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW

    def visit(folder_fd, prefix, depth):
        nonlocal total_bytes, total_files
        if depth > 32:
            return True
        # Directory descriptors and O_NOFOLLOW also protect the live storage
        # monitor against a directory being replaced by a symlink mid-scan.
        with os.scandir(folder_fd) as entries:
            for entry in entries:
                name = prefix + entry.name
                info = os.stat(entry.name, dir_fd=folder_fd, follow_symlinks=False)
                total_files += 1
                if total_files > limits.files:
                    return True
                if stat.S_ISLNK(info.st_mode):
                    records[name] = {"kind": "symlink", "target": os.readlink(entry.name, dir_fd=folder_fd)}
                elif stat.S_ISDIR(info.st_mode):
                    records[name] = {"kind": "directory"}
                    try:
                        child_fd = os.open(entry.name, directory_flags, dir_fd=folder_fd)
                    except PermissionError:
                        records[name]["snapshot_error"] = "unreadable_directory"
                        return True
                    try:
                        if visit(child_fd, name + "/", depth + 1):
                            return True
                    finally:
                        os.close(child_fd)
                elif stat.S_ISREG(info.st_mode):
                    total_bytes += info.st_size
                    if total_bytes > limits.disk_bytes:
                        return True
                    rec = {"kind": "file", "size": info.st_size}
                    if capture:
                        try:
                            fd = os.open(entry.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                                         dir_fd=folder_fd)
                        except PermissionError:
                            rec["snapshot_error"] = "unreadable_file"
                            records[name] = rec
                            return True
                        with os.fdopen(fd, "rb") as handle:
                            if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                                raise RuntimeError("File changed type during snapshot")
                            data = handle.read(limits.file_bytes + 1)
                        rec["sha256"] = _digest(data)
                        rec["sha256_complete"] = len(data) == info.st_size
                        captured = data[:limits.capture_bytes]
                        rec["text"] = captured.decode("utf-8", "replace")
                        rec["text_truncated"] = len(captured) != info.st_size
                        rec["base64"] = base64.b64encode(captured).decode("ascii")
                        rec["base64_truncated"] = len(captured) != info.st_size
                    records[name] = rec
                else:
                    records[name] = {"kind": "special"}
        return False

    root_fd = os.open(directory, directory_flags)
    try:
        overflow = visit(root_fd, "", 0)
    finally:
        os.close(root_fd)
    return records, overflow


class IsolatedExecutor:
    """Reusable runtime, disposable environment per run. Use as a context manager.

    run(code=..., callable_name="skill", args=[...], kwargs={...}, fixture_dir=...)
    returns a JSON-compatible dict. Code executes with cwd=/work. Files under
    fixture_dir are copied; source fixtures are never mutated. Symlinks, special
    files and hard-linked fixture inputs are rejected. No .env is auto-loaded.
    """

    def __init__(self, limits: SandboxLimits | None = None):
        self.limits = limits or SandboxLimits()
        self._temp = tempfile.TemporaryDirectory(prefix="skillbench-runtime-")
        self.runtime = Path(self._temp.name) / "runtime"
        self.runtime.mkdir()
        self._env = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}
        try:
            self._build_runtime()
        except BaseException:
            self.close()
            raise

    def close(self):
        if self._temp is not None:
            self._unlock(self.runtime)
            self._temp.cleanup()
            self._temp = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    @staticmethod
    def _unlock(root: Path):
        if root.exists():
            for folder, _, _ in os.walk(root, followlinks=False):
                os.chmod(folder, 0o700)

    def _build_runtime(self):
        python = Path("/usr/bin/python3").resolve()
        info = subprocess.check_output(
            [str(python), "-I", "-c", "import sysconfig; print(sysconfig.get_path('stdlib'))"],
            env=self._env, text=True,
        ).strip()
        stdlib = Path(info)
        destination = self.runtime / stdlib.relative_to("/")
        shutil.copytree(stdlib, destination, ignore=shutil.ignore_patterns(
            "__pycache__", "test", "tests", "site-packages", "dist-packages", "ensurepip"))
        dependency_info = json.loads(subprocess.check_output(
            [str(python), "-c", "import json, yaml; print(json.dumps({'path': yaml.__path__[0], 'version': yaml.__version__}))"],
            env=self._env, cwd="/", text=True))
        yaml_source = Path(dependency_info["path"])
        yaml_target = self.runtime / "packages/yaml"
        yaml_target.mkdir(parents=True)
        self.dependencies = {"PyYAML": {"version": dependency_info["version"],
                                       "implementation": "pure_python", "files": {}}}
        for source in sorted(yaml_source.glob("*.py")):
            data = source.read_bytes()
            (yaml_target / source.name).write_bytes(data)
            self.dependencies["PyYAML"]["files"][source.name] = _digest(data)
        crypto_info=json.loads(subprocess.check_output(
            [str(python),"-c","import json,cryptography,_cffi_backend; print(json.dumps({'path':cryptography.__path__[0],'version':cryptography.__version__,'cffi_path':_cffi_backend.__file__,'cffi_version':_cffi_backend.__version__}))"],
            env=self._env,cwd="/",text=True))
        crypto_root=Path(crypto_info['path'])
        self.dependencies['cryptography']={'version':crypto_info['version'],'files':{}}
        crypto_libraries=[]
        for source in sorted(crypto_root.rglob('*')):
            if not source.is_file() or source.suffix not in ['.py','.so']:continue
            relative=source.relative_to(crypto_root)
            target=self.runtime/'packages/cryptography'/relative
            target.parent.mkdir(parents=True,exist_ok=True)
            data=source.read_bytes();target.write_bytes(data)
            self.dependencies['cryptography']['files'][str(relative)]=_digest(data)
            if source.suffix=='.so':crypto_libraries.append(source)
        cffi_source=Path(crypto_info['cffi_path'])
        cffi_data=cffi_source.read_bytes()
        (self.runtime/'packages'/cffi_source.name).write_bytes(cffi_data)
        self.dependencies['_cffi_backend']={'version':crypto_info['cffi_version'],
            'files':{cffi_source.name:_digest(cffi_data)}}
        crypto_libraries.append(cffi_source)
        # Debian's cryptography 3.4.8 explicitly loads the OpenSSL 3 legacy
        # provider during initialization, even when only Fernet/AES is used.
        provider=Path('/usr/lib/x86_64-linux-gnu/ossl-modules/legacy.so')
        provider_target=self.runtime/provider.relative_to('/')
        provider_target.parent.mkdir(parents=True,exist_ok=True)
        provider_data=provider.read_bytes();provider_target.write_bytes(provider_data)
        self.dependencies['cryptography']['files'][str(provider)]=_digest(provider_data)
        crypto_libraries.append(provider)
        shutil.copyfile(python, self.runtime / "python3")
        # Resolve dependencies using only fixed system binaries, never skill code.
        libraries = [python, *stdlib.glob("lib-dynload/*.so"),*crypto_libraries]
        copied = set()
        for binary in libraries:
            report = subprocess.run(["/usr/bin/ldd", str(binary)], env=self._env,
                                    capture_output=True, text=True, check=True).stdout
            for line in report.splitlines():
                parts = line.strip().split()
                source = next((Path(part) for part in parts if part.startswith("/")), None)
                if source is None or source in copied:
                    continue
                target = self.runtime / source.relative_to("/")
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, target)
                copied.add(source)
        shutil.copyfile(Path(__file__).with_name("_sandbox_worker.py"), self.runtime / "worker.py")
        for folder, _, files in os.walk(self.runtime):
            os.chmod(folder, 0o555)
            for name in files:
                os.chmod(Path(folder) / name, 0o444)

    def _copy_fixtures(self, source: Path, target: Path):
        if source.is_symlink():
            raise ValueError("Fixture source must not be a symlink")
        source = source.resolve(strict=True)
        if not source.is_dir():
            raise ValueError("Fixture source must be a directory")
        total = 0
        count = 0
        for folder, dirs, files in os.walk(source, followlinks=False):
            relative = Path(folder).relative_to(source)
            if len(relative.parts) > 32:
                raise ValueError("Fixture nesting exceeds 32")
            for name in dirs + files:
                path = Path(folder) / name
                info = path.lstat()
                count += 1
                if count > self.limits.files:
                    raise ValueError("Too many fixture files")
                if stat.S_ISLNK(info.st_mode) or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
                    raise ValueError("Only regular fixture files and directories are accepted")
                if stat.S_ISDIR(info.st_mode):
                    (target / relative / name).mkdir(mode=0o700)
                else:
                    if info.st_nlink != 1:
                        raise ValueError("Hard-linked fixture files are not accepted")
                    total += info.st_size
                    if total > self.limits.fixture_bytes or info.st_size > self.limits.file_bytes:
                        raise ValueError("Fixture size limit exceeded")
                    shutil.copyfile(path, target / relative / name)
                    os.chmod(target / relative / name, 0o600)

    def run(self, *, code: str, callable_name: str | None = None,
            args: list | None = None, kwargs: dict | None = None,
            fixture_dir: str | Path | None = None) -> dict[str, Any]:
        if self._temp is None:
            raise RuntimeError("Executor is closed")
        request = {"code": code, "callable_name": callable_name,
                   "args": args or [], "kwargs": kwargs or {},
                   "limits": dataclasses.asdict(self.limits)}
        encoded = json.dumps(request, ensure_ascii=False).encode()
        if len(encoded) > self.limits.fixture_bytes:
            raise ValueError("Code and invocation exceed the input size limit")
        with tempfile.TemporaryDirectory(prefix="skillbench-case-") as temporary:
            root = Path(temporary) / "root"
            shutil.copytree(self.runtime, root, copy_function=os.link)
            os.chmod(root, 0o700)
            work = root / "work"
            work.mkdir(mode=0o700)
            (root / "tmp").mkdir(mode=0o700)
            if fixture_dir is not None:
                self._copy_fixtures(Path(fixture_dir), work)
            before, overflow = _snapshot(work, self.limits)
            if overflow:
                raise ValueError("Fixture exceeds sandbox storage limits")
            (root / "request.json").write_bytes(encoded)
            os.chmod(root / "request.json", 0o400)
            os.chmod(root, 0o555)
            try:
                return self._execute(root, before)
            finally:
                self._unlock(root)

    def _execute(self, root, before):
        ready_read, ready_write = os.pipe()
        result_read, result_write = os.pipe()
        env = {**self._env, "HOME": "/nonexistent", "TMPDIR": "/tmp"}
        command = ["/usr/bin/unshare", "--user", "--map-root-user", "--net", "--pid", "--fork",
                   "/usr/bin/python3", "-I", "-B", str(Path(__file__).with_name("_sandbox_worker.py")),
                   str(root), str(ready_write), str(result_write)]
        start = time.monotonic()
        try:
            process = subprocess.Popen(command, env=env, cwd="/", stdin=subprocess.DEVNULL,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       pass_fds=(ready_write, result_write), start_new_session=True)
        except BaseException:
            os.close(ready_read)
            os.close(result_read)
            raise
        finally:
            os.close(ready_write)
            os.close(result_write)
        selector = selectors.DefaultSelector()
        streams = {"stdout": process.stdout, "stderr": process.stderr,
                   "ready": ready_read, "result": result_read}
        buffers = {name: bytearray() for name in streams}
        for name, stream in streams.items():
            selector.register(stream, selectors.EVENT_READ, name)
        forced = None
        last_disk_check = start
        try:
            while selector.get_map() or process.poll() is None:
                now = time.monotonic()
                if now - start > self.limits.wall_seconds:
                    forced = forced or "timeout"
                if now - last_disk_check > 0.02 and process.poll() is None:
                    try:
                        work_files, full_work = _snapshot(root / "work", self.limits, capture=False)
                        tmp_files, full_tmp = _snapshot(root / "tmp", self.limits, capture=False)
                        combined_bytes = sum(record.get("size", 0)
                                             for record in (*work_files.values(), *tmp_files.values()))
                        if (full_work or full_tmp or combined_bytes > self.limits.disk_bytes
                                or len(work_files) + len(tmp_files) > self.limits.files):
                            inaccessible = any(record.get("snapshot_error")
                                               for record in (*work_files.values(), *tmp_files.values()))
                            forced = forced or ("snapshot_incomplete" if inaccessible else "storage_limit")
                    except (OSError, RuntimeError):
                        # Concurrent file mutation is not a completed snapshot;
                        # the next poll rechecks it. Final capture runs after exit.
                        pass
                    last_disk_check = now
                if forced is not None and process.poll() is None:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                for key, _ in selector.select(0.01):
                    fd = key.fileobj if isinstance(key.fileobj, int) else key.fileobj.fileno()
                    chunk = os.read(fd, 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    buffer = buffers[key.data]
                    if key.data == "ready":
                        remaining = 16384 - len(buffer)
                    else:
                        remaining = self.limits.output_bytes - sum(
                            len(value) for name, value in buffers.items() if name != "ready")
                    buffer.extend(chunk[:max(0, remaining)])
                    if len(chunk) > remaining:
                        forced = forced or "output_limit"
            process.wait()
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
            selector.close()
            process.stdout.close()
            process.stderr.close()
            os.close(ready_read)
            os.close(result_read)
        decoded = {key: bytes(value).decode("utf-8", "replace") for key, value in buffers.items()}
        try:
            isolation = json.loads(decoded["ready"])
        except (ValueError, TypeError, RecursionError):
            raise SandboxUnavailable("Containment setup failed: " + decoded["stderr"][:2000])
        if isolation.get("ready") is not True:
            raise SandboxUnavailable("Containment setup did not attest readiness")
        try:
            result = json.loads(decoded["result"])
            if not isinstance(result, dict):
                raise ValueError("Worker result is not an object")
        except (ValueError, TypeError, RecursionError):
            result = {"execution_error": "Missing or malformed worker result"}
        after, overflow = _snapshot(root / "work", self.limits)
        tmp_files, tmp_overflow = _snapshot(root / "tmp", self.limits, capture=False)
        combined_bytes = sum(record.get("size", 0)
                             for record in (*after.values(), *tmp_files.values()))
        if (overflow or tmp_overflow or combined_bytes > self.limits.disk_bytes
                or len(after) + len(tmp_files) > self.limits.files):
            inaccessible = any(record.get("snapshot_error")
                               for record in (*after.values(), *tmp_files.values()))
            forced = forced or ("snapshot_incomplete" if inaccessible else "storage_limit")
        changes = {path: data for path, data in after.items() if before.get(path) != data}
        return {"status": forced or ("ok" if process.returncode == 0 and not result.get("execution_error") else "execution_error"),
                "return_value": result.get("return_value"),
                "execution_error": result.get("execution_error"),
                "stdout": decoded["stdout"], "stderr": decoded["stderr"],
                "exit_code": process.returncode, "elapsed_seconds": time.monotonic() - start,
                "changed_files": changes, "deleted_files": sorted(set(before) - set(after)),
                "files": after, "file_snapshot_truncated": overflow,
                "isolation": isolation, "limits": dataclasses.asdict(self.limits),
                "invocation_sha256": _digest((root / "request.json").read_bytes()),
                "dependencies": self.dependencies,
                "result_trust": "worker return values and streams are untrusted; file snapshots are supervisor-observed"}
