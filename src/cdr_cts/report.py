"""Run reports: JSON for machines, a table for people."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import CDS_VERSION, TEST_PLAN_VERSION, __version__
from .scenario import ScenarioResult, Status


@dataclass
class RunReport:
    data_holder: str
    started_at: datetime
    finished_at: datetime | None = None
    results: list[ScenarioResult] = field(default_factory=list)

    def counts(self) -> dict[str, int]:
        counts = {s.value: 0 for s in (Status.PASS, Status.FAIL, Status.ERROR, Status.SKIP)}
        for result in self.results:
            counts[result.status.value] += 1
        return counts

    @property
    def ok(self) -> bool:
        """True when nothing failed or errored (skips are reported, not fatal)."""
        return not any(r.status in (Status.FAIL, Status.ERROR) for r in self.results)

    def to_dict(self) -> dict:
        return {
            "harness": {"name": "cdr-dh-cts", "version": __version__},
            "test_plan": TEST_PLAN_VERSION,
            "cds_version": CDS_VERSION,
            "data_holder": self.data_holder,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "summary": self.counts(),
            "scenarios": [r.to_dict() for r in self.results],
        }

    def write_json(self, out_dir: Path) -> Path:
        out_dir.mkdir(parents=True, exist_ok=True)
        stamp = self.started_at.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        path = out_dir / f"cts-report-{stamp}.json"
        path.write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")
        return path


def now() -> datetime:
    return datetime.now(timezone.utc)


def render(report: RunReport, *, verbose: bool = False) -> str:
    lines = [
        f"CDR DH CTS harness {__version__} — test plan {TEST_PLAN_VERSION}, CDS {CDS_VERSION}",
        f"Data Holder: {report.data_holder or '(not configured)'}",
        "",
        f"{'#':>3}  {'Status':<6}  {'Time':>6}  Scenario",
        f"{'-' * 3}  {'-' * 6}  {'-' * 6}  {'-' * 50}",
    ]
    for r in report.results:
        lines.append(f"{r.number:>3}  {r.status.value:<6}  {r.duration:>5.1f}s  {r.title}")
        if r.reason:
            lines.append(f"{'':>19}  {r.reason}")
        for step in r.steps:
            if verbose or step.status in (Status.FAIL, Status.ERROR):
                detail = f" — {step.detail}" if step.detail else ""
                lines.append(f"{'':>19}  [{step.status.value}] {step.title}{detail}")
    counts = report.counts()
    lines += ["", "  ".join(f"{k}: {v}" for k, v in counts.items())]
    return "\n".join(lines)
