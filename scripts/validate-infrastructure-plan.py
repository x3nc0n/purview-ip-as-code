#!/usr/bin/env python3
"""Validate the approved scanner lab plan and its security pairings."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from jsonschema import Draft4Validator, FormatChecker


ROOT = Path(__file__).resolve().parents[1]
PLAN = ROOT / ".azure" / "infrastructure-plan.json"
SCHEMA = ROOT / "schemas" / "infrastructure-plan.schema.json"


def main() -> int:
    with SCHEMA.open(encoding="utf-8") as stream:
        schema = json.load(stream)
    Draft4Validator.check_schema(schema)
    with PLAN.open(encoding="utf-8") as stream:
        plan = json.load(stream)
    errors = list(
        Draft4Validator(schema, format_checker=FormatChecker()).iter_errors(plan)
    )
    problems = [f"schema: {error.message}" for error in errors]
    network = plan.get("network", {})
    security = plan.get("security", {})
    acceptance = plan.get("acceptance", {})
    if any(network.get(key) for key in ("publicIp", "inboundRdp", "inboundSmb")):
        problems.append("network: public IP, inbound RDP, and inbound SMB must remain disabled")
    if security.get("storagePublicAccess") or not security.get("storageDedicated"):
        problems.append("security: use a dedicated storage account with public access disabled")
    if not security.get("keyVaultRbac") or not security.get("keyVaultPurgeProtection"):
        problems.append("security: enable Key Vault RBAC and purge protection")
    if security.get("credentialOutputs"):
        problems.append("security: credentials must not be template outputs")
    if acceptance.get("defaultMode") != "discovery" or not acceptance.get(
        "scannerReadinessRequiresScan"
    ):
        problems.append("acceptance: scanner readiness must require a completed discovery run")
    if acceptance.get("liveDeploymentTested"):
        problems.append("acceptance: do not claim live deployment validation without evidence")
    if problems:
        print("\n".join(problems), file=sys.stderr)
        return 1
    print(f"Validated approved plan: {PLAN.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
