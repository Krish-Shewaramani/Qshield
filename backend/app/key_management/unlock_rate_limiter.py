"""Thread-safe process-local admission control for private-key unlocks.

State is intentionally in memory for this single-process prototype. It resets
on restart and does not coordinate multiple worker processes.
"""

from __future__ import annotations

import re
import threading
import time
from contextlib import AbstractContextManager
from dataclasses import dataclass, field
from typing import Callable

from .errors import KeyManagementError

_KEY_ID = re.compile(r"^[0-9a-f]{64}$")


class UnlockCooldownError(KeyManagementError):
    """The selected key is in its fixed authentication cooldown."""


class UnlockAdmissionError(KeyManagementError):
    """Global token or single-operation admission was unavailable."""


@dataclass
class _FailureState:
    failures: list[float] = field(default_factory=list)
    cooldown_until: float | None = None


class UnlockAttempt(AbstractContextManager["UnlockAttempt"]):
    def __init__(self, limiter: "UnlockRateLimiter", key_id: str | None):
        self._limiter = limiter
        self._key_id = key_id
        self._released = False

    def authentication_failed(self) -> None:
        self._limiter._authentication_failed(self._key_id)

    def authentication_succeeded(self) -> None:
        self._limiter._authentication_succeeded(self._key_id)

    def __enter__(self) -> "UnlockAttempt":
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        if not self._released:
            self._released = True
            self._limiter._operation.release()


class UnlockRateLimiter:
    """Admission policy for QSKS opens; defaults are the approved policy."""

    def __init__(
        self,
        *,
        clock: Callable[[], float] = time.monotonic,
        failure_threshold: int = 5,
        failure_window: float = 600.0,
        cooldown: float = 30.0,
        global_capacity: int = 4,
        refill_interval: float = 2.0,
        max_tracked_keys: int = 512,
    ) -> None:
        if min(failure_threshold, global_capacity, max_tracked_keys) <= 0:
            raise ValueError("limiter counts must be positive")
        if min(failure_window, cooldown, refill_interval) <= 0:
            raise ValueError("limiter intervals must be positive")
        self._clock = clock
        self.failure_threshold = failure_threshold
        self.failure_window = failure_window
        self.cooldown = cooldown
        self.global_capacity = global_capacity
        self.refill_interval = refill_interval
        self.max_tracked_keys = max_tracked_keys
        self._lock = threading.Lock()
        self._operation = threading.BoundedSemaphore(1)
        self._states: dict[str, _FailureState] = {}
        self._tokens = float(global_capacity)
        self._last_refill = clock()

    def admit(self, key_id: object) -> UnlockAttempt:
        """Acquire a token and the non-queueing single-unlock guard."""
        tracked_id = key_id if isinstance(key_id, str) and _KEY_ID.fullmatch(key_id) else None
        with self._lock:
            now = self._clock()
            self._prune(now)
            elapsed = max(0.0, now - self._last_refill)
            self._tokens = min(
                float(self.global_capacity),
                self._tokens + elapsed / self.refill_interval,
            )
            self._last_refill = max(self._last_refill, now)
            if self._tokens < 1.0:
                raise UnlockAdmissionError("private-key unlock is temporarily unavailable")

            # Every attempt that reaches this gate spends a global token,
            # including cooldown and concurrent-operation rejections.
            self._tokens -= 1.0
            state = self._states.get(tracked_id) if tracked_id is not None else None
            if state is not None and state.cooldown_until is not None and now < state.cooldown_until:
                raise UnlockCooldownError("private key is unavailable")
            if not self._operation.acquire(blocking=False):
                raise UnlockAdmissionError("private-key unlock is temporarily unavailable")
            return UnlockAttempt(self, tracked_id)

    @property
    def tracked_key_count(self) -> int:
        with self._lock:
            self._prune(self._clock())
            return len(self._states)

    def _prune(self, now: float) -> None:
        expired = []
        for identifier, state in self._states.items():
            if state.cooldown_until is not None and now >= state.cooldown_until:
                expired.append(identifier)
                continue
            state.failures[:] = [t for t in state.failures if now - t < self.failure_window]
            if not state.failures and state.cooldown_until is None:
                expired.append(identifier)
        for identifier in expired:
            del self._states[identifier]

    def _authentication_failed(self, identifier: str | None) -> None:
        if identifier is None:
            return
        with self._lock:
            now = self._clock()
            self._prune(now)
            state = self._states.get(identifier)
            if state is None:
                if len(self._states) >= self.max_tracked_keys:
                    return
                state = self._states[identifier] = _FailureState()
            if state.cooldown_until is not None and now < state.cooldown_until:
                return
            state.failures.append(now)
            if len(state.failures) >= self.failure_threshold:
                state.cooldown_until = now + self.cooldown

    def _authentication_succeeded(self, identifier: str | None) -> None:
        if identifier is not None:
            with self._lock:
                self._states.pop(identifier, None)


_default_lock = threading.Lock()
_default_limiter: UnlockRateLimiter | None = None


def shared_unlock_limiter() -> UnlockRateLimiter:
    """Return the one process-wide limiter used by default KeyStores."""
    global _default_limiter
    with _default_lock:
        if _default_limiter is None:
            _default_limiter = UnlockRateLimiter()
        return _default_limiter
