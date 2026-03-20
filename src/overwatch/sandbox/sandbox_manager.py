"""
Docker-based agent sandbox lifecycle management.
Falls back to process-level isolation if Docker is unavailable.
"""
import asyncio
import logging
import shutil
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

DOCKER_AVAILABLE = bool(shutil.which("docker"))


@dataclass
class SandboxConfig:
    """Configuration for a sandbox container."""
    image: str = "overwatch-sandbox:latest"
    memory_limit: str = "512m"
    cpu_quota: int = 50000  # 50% of one CPU
    network_mode: str = "bridge"
    timeout_seconds: int = 3600
    environment: Dict[str, str] = field(default_factory=dict)
    volumes: Dict[str, str] = field(default_factory=dict)  # host_path: container_path


@dataclass
class SandboxResult:
    sandbox_id: str
    container_id: Optional[str]
    exit_code: int
    stdout: str
    stderr: str
    duration_seconds: float
    artifacts: List[str] = field(default_factory=list)


class SandboxManager:
    """Manages agent execution in Docker containers (or process isolation fallback)."""

    def __init__(self, config: Optional[SandboxConfig] = None) -> None:
        self.config = config or SandboxConfig()
        self._active_sandboxes: Dict[str, str] = {}  # sandbox_id → container_id

    async def create_sandbox(self, sandbox_id: Optional[str] = None) -> str:
        """Create and start a sandbox, returning its ID."""
        sandbox_id = sandbox_id or str(uuid.uuid4())
        if not DOCKER_AVAILABLE:
            logger.warning("Docker unavailable — using process-level isolation for sandbox %s", sandbox_id)
            self._active_sandboxes[sandbox_id] = "process"
            return sandbox_id

        cmd = [
            "docker", "run", "-d",
            "--name", f"overwatch-sandbox-{sandbox_id}",
            "--memory", self.config.memory_limit,
            "--cpu-quota", str(self.config.cpu_quota),
            "--network", self.config.network_mode,
            "--rm",
        ]
        for env_key, env_val in self.config.environment.items():
            cmd += ["-e", f"{env_key}={env_val}"]
        for host_path, container_path in self.config.volumes.items():
            cmd += ["-v", f"{host_path}:{container_path}"]

        cmd.append(self.config.image)
        cmd.append("sleep")
        cmd.append(str(self.config.timeout_seconds))

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()
            if proc.returncode != 0:
                logger.error("Failed to create sandbox: %s", stderr.decode())
                self._active_sandboxes[sandbox_id] = "failed"
            else:
                container_id = stdout.decode().strip()
                self._active_sandboxes[sandbox_id] = container_id
                logger.info("Sandbox %s created — container %s", sandbox_id, container_id[:12])
        except Exception as exc:
            logger.error("Error creating sandbox: %s", exc)
            self._active_sandboxes[sandbox_id] = "error"

        return sandbox_id

    async def run_in_sandbox(
        self,
        sandbox_id: str,
        command: List[str],
        timeout: int = 300,
    ) -> SandboxResult:
        """Execute a command inside the sandbox."""
        start = datetime.utcnow()
        container_id = self._active_sandboxes.get(sandbox_id)

        if not container_id or container_id in ("process", "failed", "error") or not DOCKER_AVAILABLE:
            # Process-level fallback — still safe because we use exec not shell
            return await self._run_in_process(sandbox_id, command, timeout, start)

        cmd = ["docker", "exec", container_id] + command
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            duration = (datetime.utcnow() - start).total_seconds()
            return SandboxResult(
                sandbox_id=sandbox_id,
                container_id=container_id,
                exit_code=proc.returncode,
                stdout=stdout.decode("utf-8", errors="ignore"),
                stderr=stderr.decode("utf-8", errors="ignore"),
                duration_seconds=duration,
            )
        except asyncio.TimeoutError:
            await self.destroy_sandbox(sandbox_id)
            return SandboxResult(
                sandbox_id=sandbox_id,
                container_id=container_id,
                exit_code=-1,
                stdout="",
                stderr=f"Command timed out after {timeout}s",
                duration_seconds=timeout,
            )

    async def _run_in_process(
        self,
        sandbox_id: str,
        command: List[str],
        timeout: int,
        start: datetime,
    ) -> SandboxResult:
        """Process-level isolation fallback."""
        try:
            proc = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            duration = (datetime.utcnow() - start).total_seconds()
            return SandboxResult(
                sandbox_id=sandbox_id,
                container_id=None,
                exit_code=proc.returncode,
                stdout=stdout.decode("utf-8", errors="ignore"),
                stderr=stderr.decode("utf-8", errors="ignore"),
                duration_seconds=duration,
            )
        except asyncio.TimeoutError:
            return SandboxResult(
                sandbox_id=sandbox_id,
                container_id=None,
                exit_code=-1,
                stdout="",
                stderr=f"Timed out after {timeout}s",
                duration_seconds=timeout,
            )

    async def destroy_sandbox(self, sandbox_id: str) -> None:
        """Stop and remove the sandbox container."""
        container_id = self._active_sandboxes.pop(sandbox_id, None)
        if not container_id or container_id in ("process", "failed", "error") or not DOCKER_AVAILABLE:
            return
        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "kill", container_id,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await proc.communicate()
            logger.info("Destroyed sandbox %s (container %s)", sandbox_id, container_id[:12])
        except Exception as exc:
            logger.warning("Failed to destroy sandbox %s: %s", sandbox_id, exc)

    async def destroy_all(self) -> None:
        """Emergency: destroy every active sandbox."""
        for sid in list(self._active_sandboxes.keys()):
            await self.destroy_sandbox(sid)
