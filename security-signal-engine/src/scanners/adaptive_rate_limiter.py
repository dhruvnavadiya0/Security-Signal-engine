"""
Adaptive Rate Limiter — intelligent request pacing for DAST scanning.

Solves the technical limitation found in OWASP ZAP where aggressive
active scanning overwhelms targets, causing dropped connections, crashed
servers, or WAF/rate-limit triggers.

Strategy:
  - Tracks rolling response times and HTTP error rates in real-time.
  - Automatically increases delay between requests when the target
    shows signs of stress (slow responses, 429/500 errors, timeouts).
  - Recovers speed when the target stabilizes.
  - Exposes live health metrics for logging and reporting.

This is a pure Python module with no external dependencies beyond stdlib.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

logger = logging.getLogger(__name__)


class TargetHealthState(str, Enum):
    """Current assessed health of the scan target."""
    HEALTHY = "HEALTHY"          # Normal operation
    DEGRADED = "DEGRADED"        # Elevated response times or some errors
    STRESSED = "STRESSED"        # High error rate or very slow responses
    UNRESPONSIVE = "UNRESPONSIVE"  # Timeouts or connection failures


@dataclass
class ResponseMetrics:
    """Metrics for a single HTTP response."""
    status_code: int
    response_time_ms: float
    is_timeout: bool = False
    is_connection_error: bool = False
    timestamp: float = field(default_factory=time.monotonic)


@dataclass
class RateLimiterStats:
    """Snapshot of rate limiter state for reporting."""
    total_requests: int = 0
    total_errors: int = 0
    total_throttled: int = 0
    current_delay_ms: float = 0
    avg_response_time_ms: float = 0
    target_health: TargetHealthState = TargetHealthState.HEALTHY
    error_rate_pct: float = 0.0
    window_size: int = 0


class AdaptiveRateLimiter:
    """
    Real-time adaptive rate limiter for DAST scanning.

    Monitors target health via a sliding window of recent responses
    and dynamically adjusts inter-request delay.

    Usage:
        limiter = AdaptiveRateLimiter()
        limiter.acquire()           # Blocks/sleeps if throttled
        response = httpx.get(...)   # Make request
        limiter.record_response(
            status_code=response.status_code,
            response_time_ms=elapsed_ms
        )
    """

    # Thresholds for health state transitions
    HEALTHY_ERROR_RATE = 0.05       # < 5% errors → HEALTHY
    DEGRADED_ERROR_RATE = 0.15      # 5-15% errors → DEGRADED
    STRESSED_ERROR_RATE = 0.30      # 15-30% errors → STRESSED
    # > 30% → UNRESPONSIVE

    # Response time thresholds (ms)
    HEALTHY_RT_MS = 2000            # < 2s average → healthy
    DEGRADED_RT_MS = 5000           # 2-5s average → degraded
    STRESSED_RT_MS = 10000          # 5-10s average → stressed

    # Delay settings (ms)
    MIN_DELAY_MS = 50               # Minimum inter-request delay
    MAX_DELAY_MS = 5000             # Maximum inter-request delay
    BACKOFF_FACTOR = 1.5            # Multiplicative backoff on stress
    RECOVERY_FACTOR = 0.8           # Multiplicative recovery on healthy

    # Sliding window
    DEFAULT_WINDOW_SIZE = 50        # Number of recent responses to consider

    # Error status codes
    ERROR_CODES = {429, 500, 502, 503, 504}

    def __init__(
        self,
        window_size: int = DEFAULT_WINDOW_SIZE,
        min_delay_ms: float = MIN_DELAY_MS,
        max_delay_ms: float = MAX_DELAY_MS,
        enabled: bool = True,
    ):
        self._window_size = window_size
        self._min_delay_ms = min_delay_ms
        self._max_delay_ms = max_delay_ms
        self._enabled = enabled

        self._history: deque[ResponseMetrics] = deque(maxlen=window_size)
        self._current_delay_ms: float = min_delay_ms
        self._last_request_time: float = 0.0
        self._health: TargetHealthState = TargetHealthState.HEALTHY

        # Thread safety and staggering
        self._lock = threading.Lock()
        self._next_allowed_time: float = 0.0

        # Counters
        self._total_requests: int = 0
        self._total_errors: int = 0
        self._total_throttled: int = 0

    @property
    def health(self) -> TargetHealthState:
        """Current assessed target health."""
        return self._health

    @property
    def current_delay_ms(self) -> float:
        """Current inter-request delay in milliseconds."""
        return self._current_delay_ms

    def acquire(self) -> None:
        """
        Acquire permission to make a request.

        Sleeps for the current delay duration if adaptive rate limiting
        is active. Call this BEFORE making each HTTP request. Ensures
        thread-safe, strictly staggered execution of requests.
        """
        if not self._enabled:
            return

        with self._lock:
            self._total_requests += 1
            now = time.monotonic()
            
            # Use max(current_delay_ms, MIN_DELAY_MS) as the enforced delay
            delay_seconds = max(self._current_delay_ms, self._min_delay_ms) / 1000.0
            
            if self._next_allowed_time > now:
                sleep_time = self._next_allowed_time - now
                time.sleep(sleep_time)
                self._total_throttled += 1
                self._next_allowed_time += delay_seconds
            else:
                self._next_allowed_time = now + delay_seconds

            self._last_request_time = time.monotonic()

    def record_response(
        self,
        status_code: int,
        response_time_ms: float,
        is_timeout: bool = False,
        is_connection_error: bool = False,
    ) -> None:
        """
        Record a response and update the adaptive delay.

        Call this AFTER each HTTP request completes (or fails).

        Args:
            status_code: HTTP status code (0 for connection errors).
            response_time_ms: Time taken for the request in milliseconds.
            is_timeout: Whether the request timed out.
            is_connection_error: Whether a connection error occurred.
        """
        if not self._enabled:
            return

        metric = ResponseMetrics(
            status_code=status_code,
            response_time_ms=response_time_ms,
            is_timeout=is_timeout,
            is_connection_error=is_connection_error,
        )
        self._history.append(metric)

        if status_code in self.ERROR_CODES or is_timeout or is_connection_error:
            self._total_errors += 1

        self._update_health()
        self._adjust_delay()

    def _update_health(self) -> None:
        """Re-assess target health based on sliding window metrics."""
        if len(self._history) < 3:
            return  # Not enough data yet

        error_count = sum(
            1 for m in self._history
            if m.status_code in self.ERROR_CODES
            or m.is_timeout
            or m.is_connection_error
        )
        error_rate = error_count / len(self._history)

        avg_rt = sum(m.response_time_ms for m in self._history) / len(self._history)

        prev_health = self._health

        # Determine health state (worst of error rate or response time)
        if error_rate > self.STRESSED_ERROR_RATE or avg_rt > self.STRESSED_RT_MS:
            self._health = TargetHealthState.UNRESPONSIVE
        elif error_rate > self.DEGRADED_ERROR_RATE or avg_rt > self.DEGRADED_RT_MS:
            self._health = TargetHealthState.STRESSED
        elif error_rate > self.HEALTHY_ERROR_RATE or avg_rt > self.HEALTHY_RT_MS:
            self._health = TargetHealthState.DEGRADED
        else:
            self._health = TargetHealthState.HEALTHY

        if self._health != prev_health:
            logger.info(
                "Target health changed: %s → %s "
                "(error_rate=%.1f%%, avg_rt=%.0fms, window=%d)",
                prev_health.value,
                self._health.value,
                error_rate * 100,
                avg_rt,
                len(self._history),
            )

    def _adjust_delay(self) -> None:
        """Adjust inter-request delay based on current health state."""
        if self._health == TargetHealthState.HEALTHY:
            # Recover — decrease delay
            self._current_delay_ms = max(
                self._min_delay_ms,
                self._current_delay_ms * self.RECOVERY_FACTOR,
            )
        elif self._health == TargetHealthState.DEGRADED:
            # Slight increase
            self._current_delay_ms = min(
                self._max_delay_ms,
                max(self._current_delay_ms * 1.2, 200),
            )
        elif self._health == TargetHealthState.STRESSED:
            # Aggressive backoff
            self._current_delay_ms = min(
                self._max_delay_ms,
                max(self._current_delay_ms * self.BACKOFF_FACTOR, 500),
            )
        elif self._health == TargetHealthState.UNRESPONSIVE:
            # Maximum delay
            self._current_delay_ms = self._max_delay_ms

    def get_stats(self) -> RateLimiterStats:
        """Get current rate limiter statistics for reporting."""
        avg_rt = 0.0
        error_rate = 0.0
        if self._history:
            avg_rt = sum(m.response_time_ms for m in self._history) / len(self._history)
            error_count = sum(
                1 for m in self._history
                if m.status_code in self.ERROR_CODES
                or m.is_timeout
                or m.is_connection_error
            )
            error_rate = (error_count / len(self._history)) * 100

        return RateLimiterStats(
            total_requests=self._total_requests,
            total_errors=self._total_errors,
            total_throttled=self._total_throttled,
            current_delay_ms=round(self._current_delay_ms, 1),
            avg_response_time_ms=round(avg_rt, 1),
            target_health=self._health,
            error_rate_pct=round(error_rate, 1),
            window_size=len(self._history),
        )

    def reset(self) -> None:
        """Reset all state. Useful between scan targets."""
        with self._lock:
            self._history.clear()
            self._current_delay_ms = self._min_delay_ms
            self._last_request_time = 0.0
            self._next_allowed_time = 0.0
            self._health = TargetHealthState.HEALTHY
            self._total_requests = 0
            self._total_errors = 0
            self._total_throttled = 0
