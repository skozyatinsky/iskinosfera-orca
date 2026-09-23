#!/usr/bin/env python3
# ======================================================================
# verify_platform_protection.py — version 2.0
# Diagnostic validator. A local JSON file can never enable automatic merge.
# ======================================================================
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

import jsonschema


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--attestation", required=True)
    parser.add_argument("--provider-response", required=True)
    parser.add_argument("--schema", default="schemas/platform_protection_attestation.schema.json")
    parser.add_argument("--orchestrator-db")
    parser.add_argument("--repository-root", default=".")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    try:
        data = json.loads(Path(args.attestation).read_text(encoding="utf-8-sig"))
        schema = json.loads(Path(args.schema).read_text(encoding="utf-8-sig"))
        jsonschema.validate(data, schema)
        actual = hashlib.sha256(Path(args.provider_response).read_bytes()).hexdigest()
        if actual != data["provider_response_sha256"]:
            raise RuntimeError("PLATFORM_PROTECTION_RESPONSE_DIGEST_MISMATCH")
        if args.apply:
            raise RuntimeError("LOCAL_PROVIDER_JSON_NOT_AUTHORITY")
    except (OSError, ValueError, json.JSONDecodeError, jsonschema.ValidationError, RuntimeError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print("PLATFORM_PROTECTION_DIAGNOSTIC_VALID")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
