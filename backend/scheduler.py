import asyncio
import logging
from typing import Awaitable, Callable, Optional

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger

log = logging.getLogger("dws.scheduler")

_JOB_ID = "scheduled-scan"


class ScanScheduler:
    def __init__(self, run_callable: Callable[[], Awaitable[None]]):
        self._run = run_callable
        self._scheduler: Optional[AsyncIOScheduler] = None

    def start(self) -> None:
        if self._scheduler is None:
            self._scheduler = AsyncIOScheduler()
            self._scheduler.start()
            log.info("scheduler started")

    def shutdown(self) -> None:
        if self._scheduler:
            self._scheduler.shutdown(wait=False)
            self._scheduler = None
            log.info("scheduler stopped")

    def apply(self, *, enabled: bool, interval_hours: int) -> None:
        """Reconcile the scheduled job with the desired state."""
        if self._scheduler is None:
            self.start()
        assert self._scheduler is not None

        existing = self._scheduler.get_job(_JOB_ID)
        if not enabled:
            if existing:
                self._scheduler.remove_job(_JOB_ID)
                log.info("scheduled scan disabled")
            return

        hours = max(1, int(interval_hours or 6))
        trigger = IntervalTrigger(hours=hours)
        if existing:
            self._scheduler.reschedule_job(_JOB_ID, trigger=trigger)
            log.info("scheduled scan rescheduled to every %dh", hours)
        else:
            self._scheduler.add_job(
                self._wrapped, trigger=trigger, id=_JOB_ID,
                coalesce=True, max_instances=1, replace_existing=True,
            )
            log.info("scheduled scan enabled (every %dh)", hours)

    async def _wrapped(self) -> None:
        try:
            await self._run()
        except Exception:
            log.exception("scheduled scan failed")

    def next_run_time(self) -> Optional[str]:
        if self._scheduler is None:
            return None
        job = self._scheduler.get_job(_JOB_ID)
        if not job or job.next_run_time is None:
            return None
        return job.next_run_time.isoformat()
