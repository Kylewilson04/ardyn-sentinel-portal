"""
Real-time Event Bus for ADS Pipeline Monitoring

Simple in-process async event bus that enables the ADS pipeline
to emit events that get streamed to monitoring dashboards via SSE.
"""
import asyncio
import logging
import time
from typing import Dict, Any, Optional
from dataclasses import dataclass, asdict

logger = logging.getLogger(__name__)

@dataclass
class PipelineEvent:
    """Pipeline event with consistent structure"""
    event_type: str  # system_status, pipeline_start, pipeline_step, pipeline_complete, certificate_issued, error
    timestamp: float
    job_id: Optional[str] = None
    data: Dict[str, Any] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        result = asdict(self)
        if result['data'] is None:
            result['data'] = {}
        return result

class EventBus:
    """
    Simple async event bus for real-time pipeline monitoring.

    Supports multiple clients (browser tabs) and automatic cleanup
    of disconnected clients.
    """

    def __init__(self):
        self._subscribers: Dict[str, asyncio.Queue] = {}
        self._last_heartbeat = time.time()

    def subscribe(self, client_id: str) -> asyncio.Queue:
        """Subscribe a new client to the event stream"""
        queue = asyncio.Queue(maxsize=100)  # Prevent memory buildup
        self._subscribers[client_id] = queue
        logger.info(f"Client {client_id} subscribed to event bus ({len(self._subscribers)} total)")
        return queue

    def unsubscribe(self, client_id: str):
        """Remove a client from the event stream"""
        if client_id in self._subscribers:
            del self._subscribers[client_id]
            logger.info(f"Client {client_id} unsubscribed from event bus ({len(self._subscribers)} total)")

    async def emit(self, event: PipelineEvent):
        """Emit an event to all subscribers"""
        if not self._subscribers:
            return  # No one listening

        event_data = event.to_dict()
        dead_clients = []

        for client_id, queue in self._subscribers.items():
            try:
                # Non-blocking put, drop if queue is full
                queue.put_nowait(event_data)
            except asyncio.QueueFull:
                logger.warning(f"Client {client_id} queue full, dropping event")
            except Exception as e:
                logger.error(f"Failed to send event to client {client_id}: {e}")
                dead_clients.append(client_id)

        # Clean up dead clients
        for client_id in dead_clients:
            self.unsubscribe(client_id)

    async def emit_system_status(self, status_data: Dict[str, Any]):
        """Emit a system status heartbeat"""
        await self.emit(PipelineEvent(
            event_type="system_status",
            timestamp=time.time(),
            data=status_data
        ))
        self._last_heartbeat = time.time()

    async def emit_pipeline_start(self, job_id: str, vertical: str):
        """Emit pipeline start event"""
        await self.emit(PipelineEvent(
            event_type="pipeline_start",
            timestamp=time.time(),
            job_id=job_id,
            data={"vertical": vertical}
        ))

    async def emit_pipeline_step(self, job_id: str, step_name: str, duration_ms: Optional[int] = None, details: Optional[Dict] = None):
        """Emit pipeline step completion event"""
        data = {"step_name": step_name}
        if duration_ms is not None:
            data["duration_ms"] = duration_ms
        if details:
            data.update(details)

        await self.emit(PipelineEvent(
            event_type="pipeline_step",
            timestamp=time.time(),
            job_id=job_id,
            data=data
        ))

    async def emit_pipeline_complete(self, job_id: str, certificate_hash: str, total_duration_ms: int):
        """Emit pipeline completion event"""
        await self.emit(PipelineEvent(
            event_type="pipeline_complete",
            timestamp=time.time(),
            job_id=job_id,
            data={
                "certificate_hash": certificate_hash,
                "total_duration_ms": total_duration_ms
            }
        ))

    async def emit_certificate_issued(self, job_id: str, vertical: str, cert_hash: str):
        """Emit certificate issued event"""
        await self.emit(PipelineEvent(
            event_type="certificate_issued",
            timestamp=time.time(),
            job_id=job_id,
            data={
                "vertical": vertical,
                "certificate_hash": cert_hash
            }
        ))

    async def emit_error(self, job_id: Optional[str], error_message: str, step_name: Optional[str] = None):
        """Emit error event"""
        data = {"error_message": error_message}
        if step_name:
            data["step_name"] = step_name

        await self.emit(PipelineEvent(
            event_type="error",
            timestamp=time.time(),
            job_id=job_id,
            data=data
        ))

    def get_stats(self) -> Dict[str, Any]:
        """Get event bus statistics"""
        return {
            "connected_clients": len(self._subscribers),
            "last_heartbeat": self._last_heartbeat,
            "uptime_seconds": time.time() - self._last_heartbeat if self._last_heartbeat else 0
        }

# Global event bus instance
event_bus = EventBus()

# Convenience functions for pipeline instrumentation
async def emit_pipeline_start(job_id: str, vertical: str = "default"):
    """Convenience function to emit pipeline start"""
    await event_bus.emit_pipeline_start(job_id, vertical)

async def emit_pipeline_step(job_id: str, step_name: str, duration_ms: Optional[int] = None, **details):
    """Convenience function to emit pipeline step"""
    await event_bus.emit_pipeline_step(job_id, step_name, duration_ms, details)

async def emit_pipeline_complete(job_id: str, certificate_hash: str, total_duration_ms: int):
    """Convenience function to emit pipeline complete"""
    await event_bus.emit_pipeline_complete(job_id, certificate_hash, total_duration_ms)

async def emit_certificate_issued(job_id: str, vertical: str, cert_hash: str):
    """Convenience function to emit certificate issued"""
    await event_bus.emit_certificate_issued(job_id, vertical, cert_hash)

async def emit_error(job_id: Optional[str], error_message: str, step_name: Optional[str] = None):
    """Convenience function to emit error"""
    await event_bus.emit_error(job_id, error_message, step_name)
