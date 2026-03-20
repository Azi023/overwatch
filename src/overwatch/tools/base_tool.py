"""
Abstract base class for all Overwatch tool integrations.

Every tool must subclass BaseTool and implement execute() and parse_output().
The base class provides:
- Binary availability checking
- Scope enforcement delegation
- Safe subprocess execution (no shell=True)
- Target injection-character validation
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
import asyncio
import logging
import shutil
import time

logger = logging.getLogger(__name__)


@dataclass
class ToolResult:
    """Standardised result returned by every tool execution."""

    tool_name: str
    target: str
    success: bool
    raw_output: str = ""
    parsed_output: Dict[str, Any] = field(default_factory=dict)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    error: Optional[str] = None
    duration_ms: int = 0
    command: Optional[str] = None
    evidence: Dict[str, Any] = field(default_factory=dict)


# Characters that must never appear in a target string — they indicate
# an attempted shell-injection attack.
_INJECTION_CHARS: frozenset = frozenset(
    "; & | ` $ ( ) < > \n \\ \" ' { } [ ] * ? ~ ! #".split()
)

# Whitelist regex: targets may only contain safe characters.
# Allows: alphanumerics, dots, hyphens, colons, slashes, underscores, @, =, %,
# commas (for port ranges), plus (IPv6).  Everything else is rejected.
import re as _re
_SAFE_TARGET_RE = _re.compile(r'^[a-zA-Z0-9._:/@=+%,\-]+$')


class BaseTool(ABC):
    """
    Abstract base for all security tool integrations.

    Subclasses must declare:
        name          – canonical tool identifier (used as dict key)
        description   – one-line human description
        requires_binary – binary name passed to shutil.which, or None

    Subclasses must implement:
        execute()     – run the tool, return ToolResult
        parse_output() – convert raw stdout to structured dict
    """

    name: str = ""
    description: str = ""
    requires_binary: Optional[str] = None

    def __init__(self, scope_enforcer=None, timeout: int = 300) -> None:
        self._scope_enforcer = scope_enforcer
        self.timeout = timeout
        self._log = logging.getLogger(
            f"{__name__}.{self.__class__.__name__}"
        )

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------

    def is_available(self) -> bool:
        """Return True only when the required binary is present on PATH."""
        if self.requires_binary is None:
            return True
        return shutil.which(self.requires_binary) is not None

    def _check_scope(self, target: str) -> bool:
        """
        Delegate scope check to the injected ScopeEnforcer.

        When no enforcer is configured every target is considered in-scope
        (useful for testing and standalone usage).
        """
        if self._scope_enforcer is None:
            return True
        try:
            result = self._scope_enforcer.check_action("vulnerability_scan", target)
            return result.allowed
        except Exception as exc:
            self._log.error("Scope check raised an exception: %s", exc)
            return False

    def _validate_target(self, target: str) -> bool:
        """
        Reject targets that contain shell-injection characters.

        Uses both a blocklist AND a whitelist regex for defense-in-depth.
        Returns True when the target is safe to pass to a subprocess command.
        """
        if not target or not target.strip():
            return False
        for char in _INJECTION_CHARS:
            if char in target:
                self._log.warning(
                    "Potential injection character %r detected in target %r",
                    char,
                    target,
                )
                return False
        # Whitelist check: only allow known-safe characters
        if not _SAFE_TARGET_RE.match(target):
            self._log.warning(
                "Target %r contains characters outside the safe whitelist",
                target,
            )
            return False
        return True

    # ------------------------------------------------------------------
    # Subprocess runner
    # ------------------------------------------------------------------

    async def _run_process(
        self,
        cmd: List[str],
        timeout: int = None,
    ) -> Tuple[str, str, int]:
        """
        Run *cmd* as a subprocess without a shell.

        Args:
            cmd:     Argument list; index-0 is the binary path/name.
            timeout: Override the instance-level timeout (seconds).

        Returns:
            (stdout, stderr, returncode)

        Raises:
            asyncio.TimeoutError – propagated to caller for explicit handling.
        """
        effective_timeout = timeout if timeout is not None else self.timeout
        self._log.debug("Executing: %s", " ".join(cmd))

        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                process.communicate(),
                timeout=effective_timeout,
            )
        except asyncio.TimeoutError:
            process.kill()
            await process.communicate()
            self._log.error(
                "Process timed out after %d seconds: %s",
                effective_timeout,
                " ".join(cmd),
            )
            raise

        stdout = stdout_bytes.decode("utf-8", errors="replace")
        stderr = stderr_bytes.decode("utf-8", errors="replace")
        return stdout, stderr, process.returncode

    # ------------------------------------------------------------------
    # Abstract interface
    # ------------------------------------------------------------------

    @abstractmethod
    async def execute(self, target: str, **kwargs) -> ToolResult:
        """
        Run the tool against *target*.

        Must return a ToolResult even on failure — never raise unhandled
        exceptions to the caller.
        """

    @abstractmethod
    def parse_output(self, raw: str) -> Dict[str, Any]:
        """
        Convert raw tool stdout into a structured dictionary.

        Should never raise; return an empty dict on parse failure.
        """

    # ------------------------------------------------------------------
    # Convenience
    # ------------------------------------------------------------------

    def _make_error_result(
        self,
        target: str,
        error: str,
        command: Optional[str] = None,
        duration_ms: int = 0,
    ) -> ToolResult:
        """Build a failed ToolResult with a consistent structure."""
        return ToolResult(
            tool_name=self.name,
            target=target,
            success=False,
            error=error,
            command=command,
            duration_ms=duration_ms,
        )

    def _elapsed_ms(self, start: float) -> int:
        """Return milliseconds elapsed since *start* (from time.monotonic())."""
        return int((time.monotonic() - start) * 1000)
