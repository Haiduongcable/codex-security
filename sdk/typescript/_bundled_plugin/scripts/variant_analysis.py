#!/usr/bin/env python3
"""Build and verify deterministic worklists for security variant analysis."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
from collections import Counter
from pathlib import Path, PurePosixPath
from typing import Any

MAX_INPUT_BYTES = 8 * 1024 * 1024
MAX_ROWS = 10_000
MAX_TEXT_LENGTH = 8_192
DIMENSIONS = {
    "same_sink",
    "same_source",
    "missing_control",
    "shared_dependency",
    "data_shape",
    "lifecycle_edge",
    "patch_neighborhood",
    "semantic_alias",
}
DISPOSITIONS = {
    "confirmed_variant",
    "distinct_issue",
    "suppressed",
    "not_applicable",
    "deferred",
}
CANDIDATE_FIELDS = {"path", "start_line", "symbol", "search_dimension", "rationale"}
WORKLIST_FIELDS = {
    "candidate_id",
    "path",
    "start_line",
    "symbol",
    "search_dimensions",
    "rationales",
}
RECEIPT_FIELDS = {"candidate_id", "disposition", "reason", "evidence", "proof"}
PROOF_FIELDS = {"source", "control", "sink", "impact"}
ID_PATTERN = re.compile(r"^variant-[0-9a-f]{16}$")


def text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field}: expected a non-empty string")
    normalized = value.strip()
    if len(normalized) > MAX_TEXT_LENGTH:
        raise ValueError(f"{field}: exceeds {MAX_TEXT_LENGTH} characters")
    return normalized


def positive_line(value: Any) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise ValueError("start_line: expected a positive integer")
    return value


def safe_source(path: Path) -> None:
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"{path}: expected a regular, non-symlink file")
    if path.stat().st_size > MAX_INPUT_BYTES:
        raise ValueError(f"{path}: exceeds {MAX_INPUT_BYTES} bytes")


def source_path(value: str) -> Path:
    requested = Path(value).expanduser()
    if not requested.is_absolute():
        requested = Path.cwd() / requested
    safe_source(requested)
    return requested.resolve(strict=True)


def destination_path(value: str) -> Path:
    requested = Path(value).expanduser()
    if not requested.is_absolute():
        requested = Path.cwd() / requested
    if requested.is_symlink():
        raise ValueError(f"{requested}: output must not be a symbolic link")
    return requested.resolve(strict=False)


def read_jsonl(path: Path) -> list[tuple[int, dict[str, Any]]]:
    safe_source(path)
    rows: list[tuple[int, dict[str, Any]]] = []
    with path.open(encoding="utf-8") as handle:
        for number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            if len(rows) >= MAX_ROWS:
                raise ValueError(f"{path}: exceeds {MAX_ROWS} rows")
            try:
                value = json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError(f"{path} row {number}: invalid JSON: {error.msg}") from error
            if not isinstance(value, dict):
                raise ValueError(f"{path} row {number}: expected a JSON object")
            rows.append((number, value))
    return rows


def repository_file(value: Any, repo_root: Path) -> tuple[str, Path]:
    raw = text(value, "path")
    if "\0" in raw or "\\" in raw:
        raise ValueError("path: expected a repository-relative POSIX path")
    relative = PurePosixPath(raw)
    if relative.is_absolute() or ".." in relative.parts or any(":" in part for part in relative.parts):
        raise ValueError("path: expected a safe repository-relative POSIX path")
    resolved = (repo_root / Path(*relative.parts)).resolve(strict=True)
    try:
        normalized = resolved.relative_to(repo_root).as_posix()
    except ValueError as error:
        raise ValueError("path: must resolve inside --repo-root") from error
    if not resolved.is_file():
        raise ValueError("path: expected a regular file")
    return normalized, resolved


def normalize_candidate(
    row: dict[str, Any], repo_root: Path, line_counts: dict[Path, int]
) -> dict[str, Any]:
    unknown = set(row) - CANDIDATE_FIELDS
    missing = CANDIDATE_FIELDS - set(row)
    if unknown:
        raise ValueError(f"unsupported fields {', '.join(sorted(unknown))}")
    if missing:
        raise ValueError(f"missing fields {', '.join(sorted(missing))}")
    relative, source = repository_file(row["path"], repo_root)
    line = positive_line(row["start_line"])
    if source not in line_counts:
        with source.open("rb") as handle:
            line_counts[source] = sum(1 for _ in handle)
    if line > line_counts[source]:
        raise ValueError(f"start_line: exceeds {relative}")
    dimension = text(row["search_dimension"], "search_dimension")
    if dimension not in DIMENSIONS:
        raise ValueError(f"search_dimension: unsupported value {dimension!r}")
    return {
        "path": relative,
        "start_line": line,
        "symbol": text(row["symbol"], "symbol"),
        "search_dimension": dimension,
        "rationale": text(row["rationale"], "rationale"),
    }


def candidate_identity(candidate: dict[str, Any]) -> str:
    return json.dumps(
        {
            "path": candidate["path"],
            "start_line": candidate["start_line"],
            "symbol": candidate["symbol"],
        },
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def atomic_write(path: Path, payload: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and (path.is_dir() or path.is_symlink()):
        raise ValueError(f"{path}: output must be a regular file path")
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", newline="\n", dir=path.parent, delete=False
        ) as handle:
            temporary = Path(handle.name)
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(path)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def build_worklist(args: argparse.Namespace) -> None:
    repo_root = Path(args.repo_root).expanduser().resolve(strict=True)
    if not repo_root.is_dir():
        raise ValueError("--repo-root: expected a directory")
    output = destination_path(args.out)
    inputs = sorted({source_path(value) for value in args.input})
    if output in inputs:
        raise ValueError("--out: must not also be an input")
    candidates: dict[str, dict[str, Any]] = {}
    line_counts: dict[Path, int] = {}
    total_input_bytes = 0
    total_rows = 0
    for source in inputs:
        total_input_bytes += source.stat().st_size
        if total_input_bytes > MAX_INPUT_BYTES:
            raise ValueError(f"combined inputs exceed {MAX_INPUT_BYTES} bytes")
        rows = read_jsonl(source)
        total_rows += len(rows)
        if total_rows > MAX_ROWS:
            raise ValueError(f"combined inputs exceed {MAX_ROWS} rows")
        for number, row in rows:
            try:
                candidate = normalize_candidate(row, repo_root, line_counts)
            except (OSError, ValueError) as error:
                raise ValueError(f"{source} row {number}: {error}") from error
            identity = candidate_identity(candidate)
            candidate_id = f"variant-{hashlib.sha256(identity.encode()).hexdigest()[:16]}"
            existing = candidates.get(candidate_id)
            if existing is not None and candidate_identity(existing) != identity:
                raise ValueError(f"candidate ID collision for {candidate_id}")
            combined = candidates.setdefault(
                candidate_id,
                {
                    "candidate_id": candidate_id,
                    "path": candidate["path"],
                    "start_line": candidate["start_line"],
                    "symbol": candidate["symbol"],
                    "search_dimensions": set(),
                    "rationales": set(),
                },
            )
            combined["search_dimensions"].add(candidate["search_dimension"])
            combined["rationales"].add(candidate["rationale"])
    normalized_candidates = [
        {
            **candidate,
            "search_dimensions": sorted(candidate["search_dimensions"]),
            "rationales": sorted(candidate["rationales"]),
        }
        for candidate in candidates.values()
    ]
    ordered = sorted(normalized_candidates, key=lambda item: (item["path"], item["start_line"], item["candidate_id"]))
    if len(ordered) > MAX_ROWS:
        raise ValueError(f"worklist exceeds {MAX_ROWS} rows")
    payload = "".join(json.dumps(row, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n" for row in ordered)
    if len(payload.encode("utf-8")) > MAX_INPUT_BYTES:
        raise ValueError(f"worklist exceeds {MAX_INPUT_BYTES} bytes")
    atomic_write(output, payload)


def normalize_receipt(row: dict[str, Any]) -> dict[str, Any]:
    unknown = set(row) - RECEIPT_FIELDS
    if unknown:
        raise ValueError(f"unsupported fields {', '.join(sorted(unknown))}")
    candidate_id = text(row.get("candidate_id"), "candidate_id")
    if ID_PATTERN.fullmatch(candidate_id) is None:
        raise ValueError("candidate_id: expected variant- followed by 16 lowercase hex characters")
    disposition = text(row.get("disposition"), "disposition")
    if disposition not in DISPOSITIONS:
        raise ValueError(f"disposition: unsupported value {disposition!r}")
    evidence = row.get("evidence")
    if not isinstance(evidence, list) or not evidence:
        raise ValueError("evidence: expected a non-empty array")
    normalized_evidence = [text(item, "evidence item") for item in evidence]
    result: dict[str, Any] = {
        "candidate_id": candidate_id,
        "disposition": disposition,
        "reason": text(row.get("reason"), "reason"),
        "evidence": normalized_evidence,
    }
    proof = row.get("proof")
    if disposition == "confirmed_variant":
        if not isinstance(proof, dict) or set(proof) != PROOF_FIELDS:
            raise ValueError("proof: confirmed_variant requires exactly source, control, sink, and impact")
        result["proof"] = {field: text(proof[field], f"proof.{field}") for field in sorted(PROOF_FIELDS)}
    elif "proof" in row:
        raise ValueError("proof: only confirmed_variant receipts may include proof")
    return result


def normalize_worklist_id(row: dict[str, Any]) -> str:
    if set(row) != WORKLIST_FIELDS:
        raise ValueError("expected exactly the build-worklist fields")
    candidate_id = text(row["candidate_id"], "candidate_id")
    if ID_PATTERN.fullmatch(candidate_id) is None:
        raise ValueError("invalid candidate_id")
    path = text(row["path"], "path")
    relative = PurePosixPath(path)
    if (
        path != row["path"]
        or "\0" in path
        or "\\" in path
        or relative.is_absolute()
        or not relative.parts
        or relative.as_posix() != path
        or ".." in relative.parts
        or any(":" in part for part in relative.parts)
    ):
        raise ValueError("path: expected a safe repository-relative POSIX path")
    start_line = positive_line(row["start_line"])
    symbol = text(row["symbol"], "symbol")
    if symbol != row["symbol"]:
        raise ValueError("symbol: expected canonical text")
    dimensions = row["search_dimensions"]
    if not isinstance(dimensions, list) or not dimensions:
        raise ValueError("search_dimensions: expected a non-empty array")
    normalized_dimensions = [text(item, "search_dimensions item") for item in dimensions]
    if any(item not in DIMENSIONS for item in normalized_dimensions):
        raise ValueError("search_dimensions: contains an unsupported value")
    if normalized_dimensions != dimensions or normalized_dimensions != sorted(
        set(normalized_dimensions)
    ):
        raise ValueError("search_dimensions: expected sorted unique values")
    rationales = row["rationales"]
    if not isinstance(rationales, list) or not rationales:
        raise ValueError("rationales: expected a non-empty array")
    normalized_rationales = [text(item, "rationales item") for item in rationales]
    if normalized_rationales != rationales or normalized_rationales != sorted(
        set(normalized_rationales)
    ):
        raise ValueError("rationales: expected sorted unique values")
    identity = candidate_identity(
        {"path": path, "start_line": start_line, "symbol": symbol}
    )
    expected = f"variant-{hashlib.sha256(identity.encode()).hexdigest()[:16]}"
    if candidate_id != expected:
        raise ValueError("candidate_id does not match row content")
    return candidate_id


def verify_ledger(args: argparse.Namespace) -> None:
    worklist_path = source_path(args.worklist)
    receipts_path = source_path(args.receipts)
    output = destination_path(args.out)
    if output in {worklist_path, receipts_path}:
        raise ValueError("--out: must not replace an input")
    worklist_ids: list[str] = []
    for number, row in read_jsonl(worklist_path):
        try:
            worklist_ids.append(normalize_worklist_id(row))
        except ValueError as error:
            raise ValueError(f"{worklist_path} row {number}: {error}") from error
    duplicate_work = sorted(key for key, count in Counter(worklist_ids).items() if count > 1)
    if duplicate_work:
        raise ValueError(f"worklist contains duplicate candidate IDs: {', '.join(duplicate_work)}")

    receipts: list[dict[str, Any]] = []
    for number, row in read_jsonl(receipts_path):
        try:
            receipts.append(normalize_receipt(row))
        except ValueError as error:
            raise ValueError(f"{receipts_path} row {number}: {error}") from error
    receipt_ids = [row["candidate_id"] for row in receipts]
    duplicate_receipts = sorted(key for key, count in Counter(receipt_ids).items() if count > 1)
    if duplicate_receipts:
        raise ValueError(f"receipts contain duplicate candidate IDs: {', '.join(duplicate_receipts)}")
    missing = sorted(set(worklist_ids) - set(receipt_ids))
    unknown = sorted(set(receipt_ids) - set(worklist_ids))
    if missing:
        raise ValueError(f"missing receipts for: {', '.join(missing)}")
    if unknown:
        raise ValueError(f"receipts reference unknown candidates: {', '.join(unknown)}")

    counts = Counter(row["disposition"] for row in receipts)
    digest = hashlib.sha256(worklist_path.read_bytes()).hexdigest()
    summary = {
        "schema_version": 1,
        "complete": True,
        "worklist_sha256": digest,
        "total_candidates": len(worklist_ids),
        "dispositions": {name: counts.get(name, 0) for name in sorted(DISPOSITIONS)},
    }
    atomic_write(output, json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    build = subparsers.add_parser("build-worklist", help="Normalize candidates and assign stable IDs.")
    build.add_argument("--repo-root", required=True)
    build.add_argument("--input", nargs="+", required=True)
    build.add_argument("--out", required=True)
    build.set_defaults(run=build_worklist)
    verify = subparsers.add_parser("verify-ledger", help="Verify exact candidate receipt closure.")
    verify.add_argument("--worklist", required=True)
    verify.add_argument("--receipts", required=True)
    verify.add_argument("--out", required=True)
    verify.set_defaults(run=verify_ledger)
    return parser.parse_args()


def main() -> None:
    try:
        args = parse_args()
        args.run(args)
    except (OSError, ValueError) as error:
        print(f"variant_analysis: {error}", file=sys.stderr)
        raise SystemExit(1) from error


if __name__ == "__main__":
    main()
