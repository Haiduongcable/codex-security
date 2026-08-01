import { mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";

const python = Bun.which("python3") ?? Bun.which("python") ?? Bun.which("py");
const script = join(PLUGIN_ROOT, "scripts", "variant_analysis.py");

function run(args: string[]) {
  expect(python).not.toBeNull();
  if (python === null) throw new Error("Python is required for this test.");
  return Bun.spawnSync([python, "-I", "-B", script, ...args], {
    stdout: "pipe",
    stderr: "pipe",
  });
}

async function jsonLines(path: string): Promise<Record<string, unknown>[]> {
  return (await readFile(path, "utf8"))
    .trim()
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as Record<string, unknown>);
}

describe("variant analysis ledger helper", () => {
  test("builds stable deduplicated worklists and verifies exact closure", async () => {
    const root = await mkdtemp(join(tmpdir(), "codex-security-variants-"));
    try {
      const source = join(root, "example.ts");
      const candidates = join(root, "candidates.jsonl");
      const reversed = join(root, "reversed.jsonl");
      const worklist = join(root, "worklist.jsonl");
      const secondWorklist = join(root, "worklist-second.jsonl");
      const receipts = join(root, "receipts.jsonl");
      const summary = join(root, "summary.json");
      await writeFile(
        source,
        "export function first() {}\nexport function second() {}\n",
      );
      const rows = [
        {
          path: "example.ts",
          start_line: 2,
          symbol: "second",
          search_dimension: "shared_dependency",
          rationale: "Uses the same helper through another call path.",
        },
        {
          path: "example.ts",
          start_line: 2,
          symbol: "second",
          search_dimension: "semantic_alias",
          rationale: "Uses an equivalent API for the same operation.",
        },
        {
          path: "example.ts",
          start_line: 1,
          symbol: "first",
          search_dimension: "same_sink",
          rationale: "Reaches the seed sink from another entry point.",
        },
      ];
      await writeFile(
        candidates,
        `${JSON.stringify(rows[0])}\n${JSON.stringify(rows[1])}\n${JSON.stringify(rows[0])}\n${JSON.stringify(rows[2])}\n`,
      );
      await writeFile(
        reversed,
        `${JSON.stringify(rows[2])}\n${JSON.stringify(rows[1])}\n${JSON.stringify(rows[0])}\n`,
      );

      const built = run([
        "build-worklist",
        "--repo-root",
        root,
        "--input",
        candidates,
        "--out",
        worklist,
      ]);
      expect(built.exitCode).toBe(0);
      const rebuilt = run([
        "build-worklist",
        "--repo-root",
        root,
        "--input",
        reversed,
        "--out",
        secondWorklist,
      ]);
      expect(rebuilt.exitCode).toBe(0);
      expect(await readFile(secondWorklist, "utf8")).toBe(
        await readFile(worklist, "utf8"),
      );

      const normalized = await jsonLines(worklist);
      expect(normalized).toHaveLength(2);
      expect(normalized.map((row) => row["start_line"])).toEqual([1, 2]);
      expect(normalized[1]!["search_dimensions"]).toEqual([
        "semantic_alias",
        "shared_dependency",
      ]);
      expect(
        normalized.every((row) =>
          /^variant-[0-9a-f]{16}$/u.test(String(row["candidate_id"])),
        ),
      ).toBe(true);

      await writeFile(
        receipts,
        `${JSON.stringify({
          candidate_id: normalized[0]!["candidate_id"],
          disposition: "confirmed_variant",
          reason: "The same missing control leaves this path reachable.",
          evidence: ["example.ts:1"],
          proof: {
            source: "request input",
            control: "missing boundary check",
            sink: "filesystem write",
            impact: "write outside the target directory",
          },
        })}\n${JSON.stringify({
          candidate_id: normalized[1]!["candidate_id"],
          disposition: "suppressed",
          reason: "A canonical containment check rejects escapes.",
          evidence: ["example.ts:2"],
        })}\n`,
      );
      const verified = run([
        "verify-ledger",
        "--worklist",
        worklist,
        "--receipts",
        receipts,
        "--out",
        summary,
      ]);
      expect(verified.exitCode).toBe(0);
      expect(JSON.parse(await readFile(summary, "utf8"))).toMatchObject({
        schema_version: 1,
        complete: true,
        total_candidates: 2,
        dispositions: { confirmed_variant: 1, suppressed: 1 },
      });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("rejects repository traversal and lines outside the source file", async () => {
    const root = await mkdtemp(
      join(tmpdir(), "codex-security-variants-invalid-"),
    );
    try {
      const outside = join(root, "outside.jsonl");
      const badLine = join(root, "bad-line.jsonl");
      const linkedInput = join(root, "linked.jsonl");
      const output = join(root, "worklist.jsonl");
      await writeFile(join(root, "source.py"), "pass\n");
      const base = {
        symbol: "candidate",
        search_dimension: "semantic_alias",
        rationale: "Potential semantic equivalent.",
      };
      await writeFile(
        outside,
        `${JSON.stringify({ ...base, path: "../outside.py", start_line: 1 })}\n`,
      );
      let result = run([
        "build-worklist",
        "--repo-root",
        root,
        "--input",
        outside,
        "--out",
        output,
      ]);
      expect(result.exitCode).toBe(1);
      expect(result.stderr.toString()).toContain(
        "safe repository-relative POSIX path",
      );

      await writeFile(
        badLine,
        `${JSON.stringify({ ...base, path: "source.py", start_line: 2 })}\n`,
      );
      result = run([
        "build-worklist",
        "--repo-root",
        root,
        "--input",
        badLine,
        "--out",
        output,
      ]);
      expect(result.exitCode).toBe(1);
      expect(result.stderr.toString()).toContain(
        "start_line: exceeds source.py",
      );

      await symlink(badLine, linkedInput);
      result = run([
        "build-worklist",
        "--repo-root",
        root,
        "--input",
        linkedInput,
        "--out",
        output,
      ]);
      expect(result.exitCode).toBe(1);
      expect(result.stderr.toString()).toContain(
        "expected a regular, non-symlink file",
      );
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("rejects aggregate candidate inputs beyond the verifier row limit", async () => {
    const root = await mkdtemp(
      join(tmpdir(), "codex-security-variants-limits-"),
    );
    try {
      const source = join(root, "source.py");
      const first = join(root, "first.jsonl");
      const second = join(root, "second.jsonl");
      const output = join(root, "worklist.jsonl");
      await writeFile(source, "pass\n");
      const rows = (start: number, count: number) =>
        Array.from({ length: count }, (_, offset) =>
          JSON.stringify({
            path: "source.py",
            start_line: 1,
            symbol: `candidate_${start + offset}`,
            search_dimension: "same_sink",
            rationale: "Reaches the same sink.",
          }),
        ).join("\n") + "\n";
      await writeFile(first, rows(0, 5_001));
      await writeFile(second, rows(5_001, 5_000));

      const result = run([
        "build-worklist",
        "--repo-root",
        root,
        "--input",
        first,
        second,
        "--out",
        output,
      ]);
      expect(result.exitCode).toBe(1);
      expect(result.stderr.toString()).toContain(
        "combined inputs exceed 10000 rows",
      );
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("fails closed for missing, duplicate, and unknown receipts", async () => {
    const root = await mkdtemp(
      join(tmpdir(), "codex-security-variants-ledger-"),
    );
    try {
      const worklist = join(root, "worklist.jsonl");
      const receipts = join(root, "receipts.jsonl");
      const summary = join(root, "summary.json");
      const candidateId = "variant-0123456789abcdef";
      await writeFile(
        worklist,
        `${JSON.stringify({ candidate_id: candidateId })}\n`,
      );
      await writeFile(receipts, "");
      let result = run([
        "verify-ledger",
        "--worklist",
        worklist,
        "--receipts",
        receipts,
        "--out",
        summary,
      ]);
      expect(result.exitCode).toBe(1);
      expect(result.stderr.toString()).toContain(
        `missing receipts for: ${candidateId}`,
      );

      const receipt = {
        candidate_id: candidateId,
        disposition: "suppressed",
        reason: "An effective control defeats the path.",
        evidence: ["source.ts:1"],
      };
      await writeFile(
        receipts,
        `${JSON.stringify(receipt)}\n${JSON.stringify(receipt)}\n`,
      );
      result = run([
        "verify-ledger",
        "--worklist",
        worklist,
        "--receipts",
        receipts,
        "--out",
        summary,
      ]);
      expect(result.exitCode).toBe(1);
      expect(result.stderr.toString()).toContain("duplicate candidate IDs");

      await writeFile(
        receipts,
        `${JSON.stringify({ ...receipt, proof: null })}\n`,
      );
      result = run([
        "verify-ledger",
        "--worklist",
        worklist,
        "--receipts",
        receipts,
        "--out",
        summary,
      ]);
      expect(result.exitCode).toBe(1);
      expect(result.stderr.toString()).toContain(
        "only confirmed_variant receipts may include proof",
      );

      await writeFile(
        receipts,
        `${JSON.stringify(receipt)}\n${JSON.stringify({
          ...receipt,
          candidate_id: "variant-fedcba9876543210",
        })}\n`,
      );
      result = run([
        "verify-ledger",
        "--worklist",
        worklist,
        "--receipts",
        receipts,
        "--out",
        summary,
      ]);
      expect(result.exitCode).toBe(1);
      expect(result.stderr.toString()).toContain(
        "receipts reference unknown candidates",
      );
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
