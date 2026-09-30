"""Docker sandbox preflight and bounded command execution."""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path


class SandboxError(RuntimeError):
    """Raised when a required Docker sandbox cannot be used."""


@dataclass(frozen=True)
class SandboxConfig:
    image: str = "security-signal-engine:latest"
    workspace_mount: str = "/workspace"
    network: str = "bridge"
    memory: str = "2g"
    cpus: str = "2"
    timeout_seconds: int = 120


class DockerSandbox:
    """Small Docker CLI adapter with explicit fail-closed behavior."""

    def __init__(self, config: SandboxConfig | None = None) -> None:
        self.config = config or SandboxConfig()

    def check_available(self) -> None:
        """Fail clearly instead of silently running autonomous tools on the host."""
        if shutil.which("docker") is None:
            raise SandboxError("Docker CLI was not found. Start Docker Desktop before sandboxed execution.")
        result = subprocess.run(
            ["docker", "info"], capture_output=True, text=True,
            timeout=10, check=False,
        )
        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip().splitlines()
            raise SandboxError("Docker daemon is unavailable: " + (detail[-1] if detail else "unknown error"))

    def run(self, command: list[str], workspace: str | Path) -> subprocess.CompletedProcess[str]:
        """Run a command in a bounded container with a read-write workspace mount."""
        workspace_path = Path(workspace).resolve()
        if not workspace_path.is_dir():
            raise SandboxError(f"Workspace directory does not exist: {workspace_path}")
        self.check_available()
        docker_command = [
            "docker", "run", "--rm",
            "--network", self.config.network,
            "--memory", self.config.memory,
            "--cpus", self.config.cpus,
            "--label", "sse.managed=true",
            "-v", f"{workspace_path}:{self.config.workspace_mount}",
            "-w", self.config.workspace_mount,
            self.config.image,
            *command,
        ]
        try:
            return subprocess.run(
                docker_command, capture_output=True, text=True,
                timeout=self.config.timeout_seconds, check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise SandboxError(
                f"Sandbox command exceeded {self.config.timeout_seconds}s and was stopped."
            ) from exc
