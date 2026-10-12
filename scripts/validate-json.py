#!/usr/bin/env python3
"""Validate the canonical JSON documents against the committed Draft 4 schemas."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from jsonschema import Draft4Validator, FormatChecker
from jsonschema.exceptions import SchemaError


ROOT = Path(__file__).resolve().parents[1]


def load_json(path: Path) -> object:
    with path.open(encoding="utf-8") as stream:
        return json.load(stream)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--environment",
        default=str(ROOT / "config" / "environments" / "demo.example.json"),
        help="Environment overlay to validate.",
    )
    args = parser.parse_args()

    documents = (
        (Path(args.environment), ROOT / "schemas" / "environment.schema.json"),
        (ROOT / "config" / "labels.json", ROOT / "schemas" / "config.schema.json"),
        (
            ROOT / "config" / "publishing-policies.json",
            ROOT / "schemas" / "publishing-policy.schema.json",
        ),
        (ROOT / "config" / "detection.json", ROOT / "schemas" / "detection.schema.json"),
        (
            ROOT / "config" / "auto-labeling-policies.json",
            ROOT / "schemas" / "policies.schema.json",
        ),
    )
    failures: list[str] = []
    for document_path, schema_path in documents:
        try:
            schema = load_json(schema_path)
            Draft4Validator.check_schema(schema)
            document = load_json(document_path)
            errors = sorted(
                Draft4Validator(
                    schema,
                    format_checker=FormatChecker(),
                ).iter_errors(document),
                key=lambda error: list(error.absolute_path),
            )
            for error in errors:
                location = ".".join(str(part) for part in error.absolute_path) or "<root>"
                failures.append(f"{document_path}: {location}: {error.message}")
        except (OSError, json.JSONDecodeError, SchemaError) as error:
            failures.append(f"{document_path}: {error}")

    if failures:
        print("\n".join(failures), file=sys.stderr)
        return 1
    print(f"Validated {len(documents)} JSON documents against Draft 4 schemas.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
