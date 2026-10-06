"""The real scenarios, run against the in-process fake Data Holder."""

from __future__ import annotations

import pytest

from cdr_cts.config import Config
from cdr_cts.jose import SigningKey
from cdr_cts.runner import run
from cdr_cts.scenario import Status

from .fake_dh import DISCOVERY_URL, RESOURCE_BASE, FakeDataHolder

OFFLINE = [1, 5, 7, 8, 9, 10, 12]


@pytest.fixture(scope="module")
def adr_key() -> SigningKey:
    return SigningKey.generate("PS256")


def make_config(tmp_path) -> Config:
    return Config.from_dict(
        {
            "mtls_edge": False,
            "dh": {"discovery_url": DISCOVERY_URL, "resource_base_url": RESOURCE_BASE},
            "ecosystem": {"admin_url": ""},
            "adr": {"client_id": "fake-client"},
            "tls": {"verify": False},
        },
        base_dir=tmp_path,
    )


def run_against(dh: FakeDataHolder, adr_key: SigningKey, tmp_path, numbers=OFFLINE):
    return run(make_config(tmp_path), numbers=numbers, adr_key=adr_key, transport=dh.transport())


def by_number(report):
    return {r.number: r for r in report.results}


def test_conformant_data_holder_passes(adr_key, tmp_path):
    report = run_against(FakeDataHolder(adr_key), adr_key, tmp_path)
    results = by_number(report)
    failures = {
        n: [f"{s.title}: {s.detail}" for s in r.steps if s.status is Status.FAIL] or r.reason
        for n, r in results.items()
        if r.status is not Status.PASS
    }
    assert not failures, failures
    assert report.ok


def test_lenient_client_authentication_fails_scenario_12(adr_key, tmp_path):
    report = run_against(FakeDataHolder(adr_key, lenient=True), adr_key, tmp_path, numbers=[12])
    result = by_number(report)[12]
    assert result.status is Status.FAIL
    failed = [s for s in result.steps if s.status is Status.FAIL]
    assert len(failed) == 15, [s.title for s in failed]
    assert not report.ok


def test_client_assertion_records_every_negative_case(adr_key, tmp_path):
    report = run_against(FakeDataHolder(adr_key), adr_key, tmp_path, numbers=[12])
    titles = [s.title for s in by_number(report)[12].steps if s.title.startswith("Token request")]
    assert len(titles) == 15
    assert any("'alg' none" in t for t in titles)
    assert any("RS256" in t for t in titles)


def test_scenarios_without_prerequisites_skip(adr_key, tmp_path):
    requested = [2, 3, 4, 6, 11, 13, 14]
    report = run_against(FakeDataHolder(adr_key), adr_key, tmp_path, numbers=requested)
    results = by_number(report)
    assert results[5].status is Status.PASS  # pulled in as scenario 6's dependency
    for number in requested:
        result = results[number]
        assert result.status is Status.SKIP, (number, result.status, result.reason)
        assert "missing prerequisite" in result.reason
    assert report.ok  # skips are reported, not failures


def test_dependencies_are_pulled_in(adr_key, tmp_path):
    report = run_against(FakeDataHolder(adr_key), adr_key, tmp_path, numbers=[10])
    assert [r.number for r in report.results] == [5, 9, 10]
    assert all(r.status is Status.PASS for r in report.results)


def test_unreachable_dh_endpoint_fails_the_dh_rather_than_erroring(adr_key, tmp_path):
    dh = FakeDataHolder(adr_key, unreachable=("/authorize",))
    result = by_number(run_against(dh, adr_key, tmp_path, numbers=[12]))[12]
    assert result.status is Status.FAIL
    assert "Data Holder endpoint unreachable" in result.reason
    assert "/authorize" in result.reason


def test_report_redacts_tokens(adr_key, tmp_path):
    report = run_against(FakeDataHolder(adr_key), adr_key, tmp_path, numbers=[5])
    # No compact JWS (request objects, ID tokens, assertions) leaks into the report.
    assert "eyJ" not in str(report.to_dict())
