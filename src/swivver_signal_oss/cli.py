from __future__ import annotations

import argparse
import json
from pathlib import Path

from .media import analyze


def main(*, application_factory=None):
    parser = argparse.ArgumentParser(
        description="Swivver Signal OSS: shadow media observations"
    )
    commands = parser.add_subparsers(dest="command", required=True)
    local = commands.add_parser("analyze")
    local.add_argument("video", type=Path)
    local.add_argument("--output", type=Path)
    local.add_argument("--snapshot-id", default="local")
    local.add_argument("--input-sha256")
    local.add_argument("--expected-sha256")
    server = commands.add_parser("serve")
    server.add_argument("--host", default="127.0.0.1")
    server.add_argument("--port", type=int, default=8765)
    server.add_argument("--data-dir", type=Path)
    server.add_argument("--workers", type=int)
    server.add_argument("--evidence-model", type=Path)
    server.add_argument("--multilingual-evidence-model", type=Path)
    args = parser.parse_args()
    if args.command == "serve":
        from .server import serve

        serve(
            args.host,
            args.port,
            root=args.data_dir,
            workers=args.workers,
            evidence_model=args.evidence_model,
            multilingual_evidence_model=args.multilingual_evidence_model,
            application_factory=application_factory,
        )
        return
    result = analyze(
        args.video,
        snapshot_id=args.snapshot_id,
        input_sha256=args.input_sha256,
        expected_sha256=args.expected_sha256,
    )
    text = json.dumps(result, indent=2, allow_nan=False) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text)
    else:
        print(text, end="")


if __name__ == "__main__":
    main()
