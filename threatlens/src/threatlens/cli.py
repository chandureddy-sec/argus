"""Command-line entry point: ``threatlens <command>``."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from threatlens import __version__
from threatlens.profile import ProfileError, load_pirs, load_profile
from threatlens.settings import get_settings


def _validate_profile(args: argparse.Namespace) -> int:
    s = get_settings()
    profile_path = Path(args.profile or s.profile_path)
    pirs_path = Path(args.pirs or s.pirs_path)
    try:
        profile = load_profile(profile_path)
        pirs = load_pirs(pirs_path, profile)
    except ProfileError as e:
        print(f"invalid: {e}", file=sys.stderr)
        return 1
    org = profile.org
    print(
        f"ok: {org.name} - {len(org.domains)} domains, {len(org.ip_ranges)} IP ranges, "
        f"{len(org.brands)} brands, {len(org.tech_stack)} tech-stack items; {len(pirs.pirs)} PIRs"
    )
    return 0


def _api(args: argparse.Namespace) -> int:
    import uvicorn

    uvicorn.run(
        "threatlens.api.app:create_app", factory=True, host=args.host, port=args.port, log_config=None
    )
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="threatlens", description="ThreatLens threat intelligence platform")
    parser.add_argument("--version", action="version", version=f"threatlens {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    v = sub.add_parser("validate-profile", help="validate the org profile and PIR files")
    v.add_argument("--profile", help="org profile YAML (default: TL_PROFILE_PATH)")
    v.add_argument("--pirs", help="PIR YAML (default: TL_PIRS_PATH)")
    v.set_defaults(func=_validate_profile)

    a = sub.add_parser("api", help="run the API server")
    a.add_argument("--host", default="127.0.0.1")
    a.add_argument("--port", type=int, default=8000)
    a.set_defaults(func=_api)

    args = parser.parse_args(argv)
    result: int = args.func(args)
    return result


if __name__ == "__main__":
    raise SystemExit(main())
