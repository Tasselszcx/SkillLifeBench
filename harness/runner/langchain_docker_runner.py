"""Docker-isolated LangChain runner."""

from .docker_runner import DockerRunner


class LangChainDockerRunner(DockerRunner):
    """LangChain agent execution in Docker container."""

    def __init__(
        self,
        llm_backend: str = "openai",
        model: str = "gpt-4",
        **docker_kwargs
    ):
        # Allow network for LLM API calls
        docker_kwargs.setdefault("network_mode", "bridge")
        super().__init__(**docker_kwargs)
        self.llm_backend = llm_backend
        self.model = model
