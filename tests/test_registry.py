"""The implemented scenarios must match the machine-readable test plan exactly."""

from __future__ import annotations

from pathlib import Path

import yaml

from cdr_cts import TEST_PLAN_VERSION
from cdr_cts.runner import select
from cdr_cts.scenario import all_scenarios

MANIFEST = Path(__file__).resolve().parents[1] / "scenarios" / f"tp-{TEST_PLAN_VERSION}.yaml"


def test_every_planned_scenario_is_implemented_with_matching_metadata():
    planned = {s["number"]: s for s in yaml.safe_load(MANIFEST.read_text(encoding="utf-8"))["scenarios"]}
    implemented = {cls.number: cls for cls in all_scenarios()}
    assert sorted(implemented) == sorted(planned) == list(range(1, 15))
    for number, entry in planned.items():
        cls = implemented[number]
        assert (cls.id, cls.title, cls.section) == (entry["id"], entry["title"], entry["section"]), number


def test_dependencies_point_at_earlier_scenarios():
    for cls in all_scenarios():
        assert all(dep < cls.number for dep in cls.depends_on), cls.number


def test_select_adds_dependencies_transitively_and_keeps_plan_order():
    assert [c.number for c in select([10])] == [5, 9, 10]
    assert [c.number for c in select([6, 1])] == [1, 5, 6]
    assert [c.number for c in select(None, skip=[2, 6])] == [n for n in range(1, 15) if n not in (2, 6)]
