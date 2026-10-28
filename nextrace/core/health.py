"""Health registry: every module registers a callable returning ComponentHealthV1."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable

from nextrace.contracts.ops import ComponentHealthV1, HealthReportV1

VERSION = "0.2.0"
HealthProbe = Callable[[], ComponentHealthV1]


class HealthRegistry:
    def __init__(self) -> None:
        self._probes: dict[str, HealthProbe] = {}

    def register(self, name: str, probe: HealthProbe) -> None:
        self._probes[name] = probe

    def report(self) -> HealthReportV1:
        comps: list[ComponentHealthV1] = []
        for name, probe in self._probes.items():
            try:
                comps.append(probe())
            except Exception as e:  # a failing probe is itself a health fact
                comps.append(ComponentHealthV1(name=name, status="down", detail=type(e).__name__, checked_at=datetime.now(timezone.utc)))
        statuses = {c.status for c in comps}
        overall = "down" if "down" in statuses else ("degraded" if "degraded" in statuses else "ok")
        return HealthReportV1(status=overall, at=datetime.now(timezone.utc), version=VERSION, components=comps)


def component(name: str, status: str, detail: str | None = None, **metrics: float) -> ComponentHealthV1:
    return ComponentHealthV1(name=name, status=status, detail=detail, checked_at=datetime.now(timezone.utc),
                             metrics={k: float(v) for k, v in metrics.items()})
