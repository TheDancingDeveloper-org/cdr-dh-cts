"""Run a selection of scenarios against the configured Data Holder."""

from __future__ import annotations

import time
import traceback
from collections.abc import Callable, Iterable

import httpx

from .authorize import load_callable
from .config import Config
from .ecosystem import Ecosystem
from .errors import CtsError
from .jose import SigningKey
from .report import RunReport, now
from .scenario import (
    REQUIREMENT_HINTS,
    Scenario,
    ScenarioContext,
    ScenarioResult,
    SkipScenario,
    Status,
    StepFailed,
    all_scenarios,
)
from .ssa import Participant


def participant_for(config: Config) -> Participant:
    adr = config.adr
    return Participant(
        legal_entity_id=adr.legal_entity_id,
        legal_entity_name=adr.legal_entity_name,
        brand_id=adr.brand_id,
        brand_name=adr.brand_name,
        software_product_id=adr.software_product_id,
        software_product_name=adr.software_product_name,
        scope=adr.scope,
        adr_base_url=config.adr_base_url,
    )


def select(numbers: Iterable[int] | None = None, skip: Iterable[int] = ()) -> list[type[Scenario]]:
    """Scenarios to run in plan order, pulling in the dependencies of any selected one."""
    available = {cls.number: cls for cls in all_scenarios()}
    wanted = set(available) if numbers is None else set(numbers)
    unknown = wanted - set(available)
    if unknown:
        raise CtsError(f"unknown scenario number(s): {', '.join(map(str, sorted(unknown)))}")
    pending = list(wanted)
    while pending:
        for dependency in available[pending.pop()].depends_on:
            if dependency not in wanted:
                wanted.add(dependency)
                pending.append(dependency)
    return [available[n] for n in sorted(wanted - set(skip))]


def load_adr_key(config: Config) -> SigningKey:
    path = config.adr_key_path
    if not path.exists():
        raise CtsError(f"ADR signing key not found at {path}; generate one with 'cdr-cts keys init {path.parent}'")
    return SigningKey.from_pem_file(path)


def run_scenario(ctx: ScenarioContext, cls: type[Scenario]) -> ScenarioResult:
    result = ScenarioResult(cls.number, cls.id, cls.title, cls.section, Status.PASS)
    started = time.monotonic()
    ctx.steps = result.steps

    missing = [r for r in cls.requires if not ctx.satisfies(r)]
    failed_deps = [n for n in cls.depends_on if ctx.results.get(n) is None or ctx.results[n].status is not Status.PASS]
    if missing:
        result.status = Status.SKIP
        result.reason = "missing prerequisite: " + "; ".join(REQUIREMENT_HINTS[r] for r in missing)
    elif failed_deps:
        result.status = Status.SKIP
        result.reason = "needs scenario(s) " + ", ".join(
            f"{n} ({ctx.results[n].status.value if n in ctx.results else 'not run'})" for n in failed_deps
        ) + " to pass first"
    else:
        try:
            cls().run(ctx)
            if not result.steps:
                result.status, result.reason = Status.ERROR, "scenario recorded no steps"
            elif any(s.status is Status.FAIL for s in result.steps):
                result.status = Status.FAIL
        except SkipScenario as exc:
            result.status, result.reason = Status.SKIP, str(exc)
        except StepFailed:
            result.status = Status.FAIL
        except (CtsError, httpx.HTTPError) as exc:
            result.status, result.reason = Status.ERROR, f"{type(exc).__name__}: {exc}"
        except Exception as exc:  # noqa: BLE001 — a harness bug: report it, keep running the plan
            result.status = Status.ERROR
            result.reason = f"{type(exc).__name__}: {exc} | " + traceback.format_exc(limit=3).replace("\n", " ")
    result.duration = time.monotonic() - started
    ctx.results[cls.number] = result
    return result


def run(
    config: Config,
    *,
    numbers: Iterable[int] | None = None,
    skip: Iterable[int] = (),
    adr_key: SigningKey | None = None,
    ecosystem: Ecosystem | None = None,
    progress: Callable[[ScenarioResult], None] | None = None,
    transport: httpx.BaseTransport | None = None,
) -> RunReport:
    """Run the selected scenarios. ``transport`` replaces the network (tests, proxies)."""
    selected = select(numbers, skip)
    adr_key = adr_key or load_adr_key(config)
    if ecosystem is None and config.ecosystem.admin_url:
        ecosystem = Ecosystem(config.ecosystem.admin_url, timeout=config.timeouts.http)
    adapter = load_callable(config.authorization.adapter) if config.authorization.adapter else None

    ctx = ScenarioContext(config, adr_key=adr_key, ecosystem=ecosystem, adapter=adapter, transport=transport)
    report = RunReport(data_holder=config.dh.discovery_url, started_at=now())
    try:
        if ecosystem is not None and ecosystem.reachable():
            ecosystem.set_participant(participant_for(config))
        for cls in selected:
            result = run_scenario(ctx, cls)
            report.results.append(result)
            if progress:
                progress(result)
    finally:
        ctx.close()
        report.finished_at = now()
    return report
