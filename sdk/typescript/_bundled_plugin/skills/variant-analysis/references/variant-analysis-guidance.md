# Variant Analysis Guidance

## Behavioral seed

Reduce the seed to behavior before searching:

| Element | Question |
| --- | --- |
| Source | What attacker-controlled value, identity, state, or event enters the path? |
| Control | What validation, authorization, encoding, isolation, or sequencing property should constrain it? |
| Sink | What dangerous operation or protected resource is reached? |
| Impact | What security property fails when the control is absent or bypassed? |
| Preconditions | Which deployment, feature, privilege, timing, or data conditions are required? |
| Patch discriminator | What minimal behavioral change should break the vulnerable path? |

Classify each observed seed property as either essential to the root cause or incidental to its implementation. Search with essential properties first.

## Search dimensions

Cover every applicable dimension and record any deliberate omission:

1. **Same sink, different source**: other routes, parsers, jobs, hooks, RPC methods, or package APIs reaching the dangerous operation.
2. **Same source, different sink**: alternate consumers of the same untrusted value or identity.
3. **Same missing control**: sibling handlers, wrappers, middleware exclusions, policy branches, or serializers that omit the invariant.
4. **Same shared dependency**: callers of the changed helper, guard, query builder, archive/path utility, deserializer, or authorization primitive.
5. **Same data shape**: parallel models, message types, configuration blocks, templates, or generated bindings that carry equivalent security-sensitive fields.
6. **Same lifecycle edge**: create/update, import/export, sync/async, single/bulk, REST/RPC, or read/write counterparts.
7. **Patch neighborhood**: unchanged callers and siblings that the patch did not update, including alternate implementations and copies.
8. **Semantic aliases**: framework or language equivalents of the source, control, or sink rather than exact token matches.

Use code search to enumerate, then inspect call chains and controls. Generated files, tests, examples, and vendored code may explain intent or provide negative controls, but do not report them as production variants unless they are shipped or reachable in the stated threat model.

## Candidate input contract

Write one JSON object per line. Required fields:

```json
{
  "path": "src/example.ts",
  "start_line": 42,
  "symbol": "handleUpload",
  "search_dimension": "shared_dependency",
  "rationale": "Calls the same archive extraction helper without the new destination check."
}
```

`search_dimension` must be one of `same_sink`, `same_source`, `missing_control`, `shared_dependency`, `data_shape`, `lifecycle_edge`, `patch_neighborhood`, or `semantic_alias`.

Paths must be repository-relative regular files and lines must exist. The helper rejects traversal, out-of-repository resolution, unsupported fields, oversized input, and invalid line numbers.
The generated worklist assigns one stable ID per path, line, and symbol while preserving every matching search dimension and distinct rationale in sorted arrays.

## Receipt contract

Write exactly one JSON object per deterministic `candidate_id`:

```json
{
  "candidate_id": "variant-0123456789abcdef",
  "disposition": "confirmed_variant",
  "reason": "The same missing boundary check exposes a second reachable entry point.",
  "evidence": ["src/example.ts:42", "src/archive.ts:88"],
  "proof": {
    "source": "Multipart filename from an unauthenticated request",
    "control": "No canonical destination containment check",
    "sink": "Archive member write under the extraction root",
    "impact": "Write outside the intended directory"
  }
}
```

Allowed dispositions:

- `confirmed_variant`: same root cause and independently supported source/control/sink/impact proof
- `distinct_issue`: security-relevant, but not the seed's root cause
- `suppressed`: safe or non-reportable instance with the exact defeating control, scope fact, or reachability fact named in `reason`; this includes an attack-path `ignore` decision
- `not_applicable`: search heuristic matched, but the code is not an applicable instance
- `deferred`: evidence could not be obtained; name the missing proof in `reason`

Every receipt requires a non-empty `reason` and `evidence` array. Only `confirmed_variant` accepts and requires `proof`; other dispositions must omit it. Evidence entries should be precise file/line references, test names, commands, or observed runtime results.

## Discrimination checks

Before confirming a variant, answer all of the following:

- Does the candidate violate the same invariant, rather than merely use the same primitive?
- Is the source attacker-controlled under the candidate's own interface and threat model?
- Does the full path reach the sink without an effective intervening control?
- Would the seed's minimal behavioral fix break this candidate's proof path?
- Does a safe sibling or negative control differ in the expected security-relevant way?

If the patch would not break the candidate, classify it as a distinct issue or refine the seed fingerprint.
