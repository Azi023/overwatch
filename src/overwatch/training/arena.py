"""
Training arena — spin up known-vulnerable targets and run agents against them
to measure proficiency before real engagements.
"""
import asyncio
import logging
import shutil
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

DOCKER_AVAILABLE = bool(shutil.which("docker"))


@dataclass
class TrainingTarget:
    name: str
    docker_image: str
    port: int
    url_template: str  # e.g. "http://localhost:{port}"
    expected_findings: List[Dict[str, Any]] = field(default_factory=list)
    setup_commands: List[str] = field(default_factory=list)
    warmup_seconds: int = 10


@dataclass
class ArenaRun:
    target_name: str
    agent_type: str
    started_at: datetime
    completed_at: Optional[datetime]
    findings_found: List[Dict]
    expected_findings: List[Dict]
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    proficiency_score: float = 0.0


class Arena:
    """Training environment manager for agent proficiency measurement."""

    KNOWN_TARGETS: Dict[str, TrainingTarget] = {
        "dvwa": TrainingTarget(
            name="dvwa",
            docker_image="vulnerables/web-dvwa",
            port=8181,
            url_template="http://localhost:{port}",
            warmup_seconds=15,
        ),
        "juiceshop": TrainingTarget(
            name="juiceshop",
            docker_image="bkimminich/juice-shop",
            port=8182,
            url_template="http://localhost:{port}",
            warmup_seconds=20,
        ),
    }

    def __init__(self) -> None:
        self._running_containers: Dict[str, str] = {}  # target_name → container_id

    async def start_target(self, target_name: str) -> Optional[str]:
        """Start a known-vulnerable target in Docker. Returns the URL."""
        if not DOCKER_AVAILABLE:
            logger.error("Docker is not available — cannot start training target")
            return None

        target = self.KNOWN_TARGETS.get(target_name)
        if not target:
            logger.error("Unknown training target: %s", target_name)
            return None

        # Remove any existing container with same name
        await self._stop_container(f"overwatch-training-{target_name}")

        cmd = [
            "docker", "run", "-d",
            "--name", f"overwatch-training-{target_name}",
            "-p", f"{target.port}:80",
            "--rm",
            target.docker_image,
        ]

        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await proc.communicate()

        if proc.returncode != 0:
            logger.error("Failed to start %s: %s", target_name, stderr.decode())
            return None

        container_id = stdout.decode().strip()
        self._running_containers[target_name] = container_id
        logger.info("Started %s container %s — waiting %ds", target_name, container_id[:12], target.warmup_seconds)

        await asyncio.sleep(target.warmup_seconds)
        url = target.url_template.format(port=target.port)
        return url

    async def stop_target(self, target_name: str) -> None:
        container_id = self._running_containers.pop(target_name, None)
        if container_id:
            await self._stop_container(container_id)

    async def stop_all(self) -> None:
        for name in list(self._running_containers.keys()):
            await self.stop_target(name)

    async def _stop_container(self, name_or_id: str) -> None:
        proc = await asyncio.create_subprocess_exec(
            "docker", "rm", "-f", name_or_id,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await proc.communicate()
