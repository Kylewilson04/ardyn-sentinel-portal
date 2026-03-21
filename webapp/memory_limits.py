"""Memory Limits - HIGH-012
Queue-based concurrency limiter. Instead of rejecting requests when slots
are full, queues them with a configurable wait timeout. Requests only get
rejected if the queue itself is full or the wait exceeds the deadline.

Think of it as a waiting room, not a brick wall.
"""
import asyncio
import time
import logging
from typing import Optional

logger = logging.getLogger(__name__)


class ConcurrencyLimiter:
    """
    Queue-based concurrency limiter for inference requests.

    - max_concurrent: How many requests run at once (GPU/crypto slots)
    - max_queue: How many requests can wait in line before we reject
    - queue_timeout: Max seconds a request will wait for a slot

    Flow:
      1. Request arrives → try to get a slot immediately
      2. No slot? → enter the queue (up to max_queue)
      3. Queue full? → reject with 503
      4. Wait up to queue_timeout seconds for a slot
      5. Timeout? → reject with 503 (queue was too slow)
    """

    def __init__(
        self,
        max_concurrent: int = 50,
        max_queue: int = 500,
        queue_timeout: float = 30.0,
    ):
        self.max_concurrent = max_concurrent
        self.max_queue = max_queue
        self.queue_timeout = queue_timeout
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.active_count = 0
        self.queue_count = 0
        self.total_processed = 0
        self.total_queued = 0
        self.rejected_count = 0
        self.timeout_count = 0
        self._peak_active = 0
        self._peak_queue = 0
        self._total_wait_time = 0.0

    async def acquire(self, timeout: Optional[float] = None) -> bool:
        """
        Acquire a processing slot, waiting in queue if necessary.

        Args:
            timeout: Override queue_timeout for this request.
                     For backwards compat, very small values (<=5s)
                     use the instance queue_timeout instead.

        Returns:
            True if slot acquired, False if rejected/timed out.
        """
        wait_timeout = self.queue_timeout
        if timeout is not None and timeout > 5.0:
            wait_timeout = timeout

        # Check if queue is full before waiting
        if self.queue_count >= self.max_queue:
            self.rejected_count += 1
            logger.warning(
                f"Queue full ({self.queue_count}/{self.max_queue}), "
                f"rejecting request. Active: {self.active_count}"
            )
            return False

        # Enter the queue
        self.queue_count += 1
        self.total_queued += 1
        if self.queue_count > self._peak_queue:
            self._peak_queue = self.queue_count

        wait_start = time.monotonic()
        try:
            await asyncio.wait_for(self.semaphore.acquire(), timeout=wait_timeout)
            wait_time = time.monotonic() - wait_start
            self._total_wait_time += wait_time

            self.queue_count -= 1
            self.active_count += 1
            if self.active_count > self._peak_active:
                self._peak_active = self.active_count

            if wait_time > 1.0:
                logger.info(
                    f"Request waited {wait_time:.1f}s in queue. "
                    f"Active: {self.active_count}/{self.max_concurrent}, "
                    f"Queue: {self.queue_count}"
                )
            return True

        except asyncio.TimeoutError:
            self.queue_count -= 1
            self.timeout_count += 1
            wait_time = time.monotonic() - wait_start
            logger.warning(
                f"Request timed out after {wait_time:.1f}s in queue. "
                f"Active: {self.active_count}/{self.max_concurrent}, "
                f"Queue: {self.queue_count}"
            )
            return False

    def release(self):
        """Release a slot after processing completes."""
        self.semaphore.release()
        self.active_count = max(0, self.active_count - 1)
        self.total_processed += 1

    def get_status(self) -> dict:
        """Get current concurrency + queue status."""
        avg_wait = (
            self._total_wait_time / self.total_queued
            if self.total_queued > 0
            else 0.0
        )
        return {
            "max_concurrent": self.max_concurrent,
            "max_queue": self.max_queue,
            "queue_timeout_s": self.queue_timeout,
            "active_count": self.active_count,
            "queue_count": self.queue_count,
            "available_slots": max(0, self.max_concurrent - self.active_count),
            "total_processed": self.total_processed,
            "total_queued": self.total_queued,
            "rejected_count": self.rejected_count,
            "timeout_count": self.timeout_count,
            "peak_active": self._peak_active,
            "peak_queue": self._peak_queue,
            "avg_wait_time_s": round(avg_wait, 3),
        }


# ── Global Limiter ────────────────────────────────────────────
# 50 concurrent slots (crypto pipeline on Jetson's 12 ARM cores)
# 500 queue depth (hold up to 500 waiting requests)
# 30s queue timeout (reject if waiting longer than 30s)
inference_limiter = ConcurrencyLimiter(
    max_concurrent=50,
    max_queue=500,
    queue_timeout=30.0,
)


async def check_memory_available() -> bool:
    """Check if system has enough memory available."""
    try:
        import psutil
        memory = psutil.virtual_memory()
        # Require at least 20% free memory
        return memory.percent < 80
    except ImportError:
        return True
    except Exception:
        return True
