"""Command line: ``cdr-cts list | run | keys init | mock | validate-config``."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import CDS_VERSION, TEST_PLAN_VERSION, __version__
from .config import Config, ConfigError
from .errors import CtsError
from .scenario import ScenarioResult, all_scenarios

EXIT_OK, EXIT_FAILED, EXIT_USAGE = 0, 1, 2


def _numbers(text: str) -> list[int]:
    try:
        return [int(part) for part in text.split(",") if part.strip()]
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"expected comma-separated scenario numbers, got {text!r}") from exc


def cmd_list(_: argparse.Namespace) -> int:
    print(f"DH test plan {TEST_PLAN_VERSION} (CDS {CDS_VERSION})\n")
    print(f"{'#':>3}  {'Sec':<5} {'Scenario':<50} Requires / depends on")
    for cls in all_scenarios():
        needs = ", ".join(r.value for r in cls.requires)
        if cls.depends_on:
            needs += f"; after {', '.join(map(str, cls.depends_on))}"
        print(f"{cls.number:>3}  {cls.section:<5} {cls.title:<50} {needs}")
    return EXIT_OK


def cmd_run(args: argparse.Namespace) -> int:
    from .report import render
    from .runner import run

    config = Config.load(args.config)
    if args.out:
        config.out_dir = Path(args.out)

    def progress(result: ScenarioResult) -> None:
        print(f"  {result.number:>2}  {result.status.value:<5}  {result.title}", flush=True)

    print(f"Running DH test plan {TEST_PLAN_VERSION} against {config.dh.discovery_url or '(no DH configured)'}")
    report = run(config, numbers=args.only, skip=args.skip or (), progress=progress)
    path = report.write_json(config.out_dir)
    print()
    print(render(report, verbose=args.verbose))
    print(f"\nReport: {path}")
    return EXIT_OK if report.ok else EXIT_FAILED


def cmd_keys_init(args: argparse.Namespace) -> int:
    from .jose import SigningKey

    directory = Path(args.dir)
    directory.mkdir(parents=True, exist_ok=True)
    for name in ("register.pem", "adr.pem"):
        path = directory / name
        if path.exists() and not args.force:
            print(f"kept     {path}")
            continue
        key = SigningKey.generate(args.alg)
        path.write_bytes(key.to_pem())
        print(f"created  {path}  ({args.alg}, kid {key.kid})")
    return EXIT_OK


def cmd_mock(args: argparse.Namespace) -> int:
    try:
        import uvicorn
    except ImportError:
        print("the mock needs the 'mock' extra: pip install 'cdr-dh-cts[mock]'", file=sys.stderr)
        return EXIT_USAGE
    import os

    if args.keys_dir:
        os.environ["CDR_MOCK_KEYS_DIR"] = args.keys_dir
    ssl = {"ssl_certfile": args.tls_cert, "ssl_keyfile": args.tls_key} if args.tls_cert else {}
    uvicorn.run("cdr_mocks.app:create_app", factory=True, host=args.host, port=args.port, **ssl)
    return EXIT_OK


def cmd_validate_config(args: argparse.Namespace) -> int:
    config = Config.load(args.config)
    problems = []
    if not config.dh.discovery_url:
        problems.append("dh.discovery_url is empty")
    if not config.adr_key_path.exists():
        problems.append(f"ADR key {config.adr_key_path} missing (cdr-cts keys init {config.adr.keys_dir})")
    for name in ("client", "alternate_client", "expired_client", "self_signed_client", "revoked_client"):
        pair = getattr(config.tls, name)
        for part in ("cert", "key"):
            path = getattr(pair, part)
            if path is not None and not path.exists():
                problems.append(f"tls.{name}.{part} {path} does not exist")
    for problem in problems:
        print(f"  - {problem}")
    print("configuration OK" if not problems else f"{len(problems)} problem(s)")
    return EXIT_OK if not problems else EXIT_FAILED


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cdr-cts", description="CDR Data Holder Conformance Test Suite harness")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__} (TP {TEST_PLAN_VERSION})")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("list", help="list the scenarios").set_defaults(func=cmd_list)

    run = sub.add_parser("run", help="run the test plan against the configured Data Holder")
    run.add_argument("--config", "-c", required=True)
    run.add_argument("--only", type=_numbers, help="scenario numbers, e.g. 1,4,12 (dependencies are added)")
    run.add_argument("--skip", type=_numbers, help="scenario numbers to leave out")
    run.add_argument("--out", help="report directory (default: out_dir from the config)")
    run.add_argument("--verbose", "-v", action="store_true", help="print every step, not just failures")
    run.set_defaults(func=cmd_run)

    keys = sub.add_parser("keys", help="key management")
    keys_sub = keys.add_subparsers(dest="keys_command", required=True)
    init = keys_sub.add_parser("init", help="create register.pem and adr.pem")
    init.add_argument("dir")
    init.add_argument("--alg", choices=("PS256", "ES256"), default="PS256")
    init.add_argument("--force", action="store_true", help="replace existing keys")
    init.set_defaults(func=cmd_keys_init)

    mock = sub.add_parser("mock", help="run the mock ecosystem (simulated Register and ADR)")
    mock.add_argument("--host", default="0.0.0.0")
    mock.add_argument("--port", type=int, default=8080)
    mock.add_argument("--keys-dir")
    mock.add_argument("--tls-cert", help="serve HTTPS with this certificate")
    mock.add_argument("--tls-key")
    mock.set_defaults(func=cmd_mock)

    validate = sub.add_parser("validate-config", help="check a configuration file and the files it names")
    validate.add_argument("--config", "-c", required=True)
    validate.set_defaults(func=cmd_validate_config)
    return parser


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):  # Windows consoles default to a legacy code page
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (ConfigError, CtsError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE


if __name__ == "__main__":
    raise SystemExit(main())
