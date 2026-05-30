"""Local scheduler for future-task delivery.

protoPen ships a single backend: ``LocalScheduler`` — sqlite + asyncio,
bundled, zero external services. (Unlike protoAgent, there is no remote
Workstacean backend here — protoPen is intentionally local-only.)

``server.py`` constructs it at startup and starts its polling loop; the
operator console and the agent tools see the ``SchedulerBackend`` protocol.

Every job carries an ``agent_name`` (from the agent identity) so a shared
storage path can't cross-fire another instance's scheduled prompts.
"""

from scheduler.interface import Job, SchedulerBackend
from scheduler.local import LocalScheduler

__all__ = ["Job", "LocalScheduler", "SchedulerBackend"]
