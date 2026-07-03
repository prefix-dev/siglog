# Remaining work for a production conda-forge deployment

Status as of July 2026. The items below are what stands between the current
codebase and a production transparency log for conda-forge. They are ordered
by how much they block the CEP, not by implementation effort.

Everything here assumes the completed groundwork: C2SP cosignature/v1
witness signatures (verified against pinned keys), quorum-based checkpoint
publishing (`WITNESS_QUORUM`), witness split-view CAS protection, vindex
snapshots + WAL compaction with auto-rebuild from log storage, and the
production hardening pass (graceful shutdown, worker supervision, atomic
filesystem writes, rate limiting).

---

## 1. Anchor the vindex root in the log (protocol decision needed)

**Problem.** The verifiable index (key → log indices, with prefix-tree
proofs) is served by the log operator, but nothing commits its root hash to
the witnessed checkpoint. A malicious operator can serve a correct Merkle
tree while lying in the vindex — e.g. omitting indices for a filename so a
client never sees that a patched entry exists. Proofs from the vindex
currently verify against a root hash that the *same server* provides in the
same response: circular trust.

**Proposed design.** Periodically append a special log entry committing to
the vindex state:

```json
{"type":"vindex-root","tree_size":123456,"root":"<hex prefix-tree root>"}
```

- `tree_size` is the log size the vindex covered when the root was computed;
  the anchor entry itself lands at some later index, which is fine — it
  describes the index state *at* `tree_size`.
- Publish one anchor per checkpoint interval **iff** the vindex root changed.
- Clients verify: (1) inclusion proof of the anchor entry against the
  witnessed checkpoint, (2) the vindex lookup proof against the anchored
  root. Both proofs together make lookups operator-independent.
- Monitors additionally recompute the vindex from the entries themselves and
  alert if an anchored root diverges — this is what makes a *wrong* (not
  just stale) anchor detectable.

**Also required: verifiable exclusion proofs.** `prefix_tree.rs::lookup_rec`
currently returns `found=false` without including the conflicting leaf or
sibling subtree, so a client cannot recompute the root from a negative
answer. Non-membership must include the mismatching leaf (or the divergence
node) so the proof reconstructs the anchored root. Until then, "key not in
index" is an unverifiable assertion.

**Open question for the CEP:** anchor as a log entry (above) vs. a checkpoint
extension line. Extension lines are lighter but per the cosignature spec,
witnesses make **no semantic statement** about extension lines — and they
bloat every checkpoint. The log-entry approach gets inclusion proofs for
free and keeps checkpoints minimal. Recommendation: log entry.

## 2. Ingest validation and dedup (`POST /add`)

**Problem.** The log currently accepts any bytes with a valid API key. For
conda-forge this means: no schema enforcement, no canonicalization check
(clients could log non-normalized JSON that then never matches a verifier's
recomputed hash), and no dedup — a bulk repodata-patch run that re-submits
100k unchanged entries would append 100k duplicate leaves.

**Plan.**
- Validate at ingest when `ENTRY_SCHEMA=conda-v1` is configured:
  - parse as JSON, check required fields
    (`subdir`, `filename`, `sha256`, `size`, `build`, `build_number`,
    `version`, `name`, `depends`),
  - re-serialize canonically and require byte-equality with the submission
    (reject non-canonical bodies with a 422 and the canonical form in the
    error, so publishers can fix their pipeline),
  - allow a `type: "index"` variant for freshness entries.
- Dedup by leaf hash: keep a `leaf_hash → index` table (or reuse the
  monitor's content-index machinery) and return the **existing** index with
  `200` instead of appending. This makes `POST /add` idempotent, which also
  resolves the ambiguous-commit/retry duplication noted in the review.
  Cost: one indexed lookup per add; the table grows with the log (32 bytes
  + index per entry — ~80 MB per 2M entries in SQLite/Postgres, acceptable).
- Size the dedup decision into the CEP: "a channel MUST NOT re-log an entry
  whose normalized bytes are unchanged; logs SHOULD enforce this."

## 3. CEP text fixes (spec gaps found during review)

1. **Vindex key must include the subdir.** The CEP says
   `index_key = SHA256(filename)`, but monitors enforce uniqueness per
   `(subdir, filename)` and identical filenames legitimately exist across
   subdirs. Use `SHA256(subdir + "/" + filename)`.
2. **Pin normalization to RFC 8785 (JCS)** instead of ad-hoc rules; state
   explicitly that floats are forbidden and whether `depends` arrays are
   sorted or preserved (recommendation: sorted — otherwise a patch that only
   reorders dependencies produces a spurious "new" entry).
3. **Inclusion proofs embedded in `repodata_shard_index.json` don't verify
   against a *newer* checkpoint.** A proof computed at `tree_size = T` does
   not verify against `root(T')` for `T' > T`, and tlog-tiles only serves
   the latest checkpoint. Fix: embed the size-`T` checkpoint alongside the
   proof, and have clients verify consistency `T → T'` from tiles. Keeps
   offline verification intact.
4. **Add a `channel` field** to the entry schema (or state that one log
   origin serves exactly one channel). Without it, entries are ambiguous if
   the log ever serves more than conda-forge.
5. **Witness freshness wording.** Checkpoints don't contain timestamps;
   freshness comes from cosignature/v1 timestamps. Define client freshness
   as "max cosignature timestamp within quorum ≥ now − max_skew".
6. **State the freshness window trade-off**: a mirror can serve
   up-to-`max_age`-old data undetected. Recommend `max_age` of 24h rather
   than 7 days — re-logging one small index entry per subdir per day is
   nearly free.
7. **Operator requirements section**: the log MUST never sign two different
   trees at the same size ("never fork"). Restoring from a backup that lost
   acknowledged entries forks the tree and permanently kills the log
   (witnesses refuse forever). Mandate: single writer, synchronous
   DB+object-store durability before signing, tested restore procedure, key
   ceremony / KMS for the signing key.

## 4. Scale limits to address before conda-forge full history

| Component | Current limit | Wall |
|---|---|---|
| Vindex key map | in-RAM `HashMap`, `VINDEX_MAX_KEYS` (10M default) | ~2M conda-forge artifacts fit (~several hundred MB); beyond that needs a disk-backed index (sled/rocksdb) or shard-by-prefix |
| Vindex startup | snapshot load + WAL tail replay | fine now (snapshots bound it); snapshot write is O(index) — at 2M keys expect ~1–2 s pauses per 100k entries, tune `VINDEX_SNAPSHOT_INTERVAL` |
| Monitor content index | in-RAM, unbounded, O(pending) scan per entry → O(n²) per batch | needs the DB-backed lookup path to be the primary one, plus batch-size caps |
| Monitor `validate_new_entries` | fetches all new entries inline in one HTTP request | cap per-request validation window; validate asynchronously and cosign on the next request |
| SQLite | single-writer; `lock_exclusive` is a no-op, deferred transactions can fail with `SQLITE_BUSY_SNAPSHOT` under concurrency | use Postgres in production; if SQLite must stay, issue `BEGIN IMMEDIATE` for writer transactions |

## 5. Tooling debt

- **`conda-monitor verify` does not verify.** It prints "VERIFICATION
  PASSED" without checking the vindex proof, the checkpoint signature, or an
  inclusion proof. This is the tool the CEP points users at — it must do the
  full client verification workflow (normalize → leaf hash → vindex proof
  against anchored root → inclusion proof → checkpoint signature + witness
  quorum) before anything ships.
- **Client library:** the verification workflow belongs in a Rust crate
  consumable by rattler/pixi, verified at package-download time (not per
  solve). Roll out `on_failure: warn` first.
- **litewitness interop:** the conformance suite passes against siglog's own
  witness; an end-to-end run against a real litewitness instance (Go) is
  still outstanding and is the definitive C2SP interop check.

## 6. Benchmark results (fly.io staging, July 2026)

`scripts/bench.py` against `conda-transparency-log.fly.dev` (shared-cpu-2x,
1 GB, ams; SQLite on volume; tiles on Tigris S3; vindex enabled;
`BATCH_MAX_AGE_MS=500`, `CHECKPOINT_INTERVAL=2`):

- **Writes**: 2,000 entries at concurrency 48 → 78 req/s, p50 595 ms /
  p99 686 ms, zero errors. `/add` latency ≈ `BATCH_MAX_AGE_MS` + RTT, since
  the ack waits for the durable batch commit — tune the batch age to trade
  latency for batch size.
- **Integration**: 77 entries/s in a short burst (2k entries), degrading to
  ~36 entries/s under sustained load (10k entries at concurrency 96 → 279 s
  drain; checkpoint follows ~1 s later). The integration loop writes tiles
  **sequentially**; parallelizing the S3 PUTs per cycle is the obvious lever
  (a 2M-entry bootstrap at 36/s is ~15 h — fine one-time, slow for bulk
  re-patching). Sustained write pressure also pushes `/add` p50 to ~1.5 s at
  concurrency 96 as requests queue behind batch commits.
- **Sustained-load verdict**: a 10k-entry run at concurrency 96 completed
  with zero errors and 500/500 sampled lookups verified — correctness holds;
  the limits are throughput, not integrity.
- **Reads**: checkpoint p50 236 ms, vindex lookup p50 215 ms, entry-bundle
  tiles p50 142 ms (client in EU → ams, no CDN).
- **Correctness under load**: every sampled entry (300/300) was findable
  through the vindex at the exact index assigned at write time, and the
  final checkpoint covered all writes.

The benchmark also caught a real bug on its first run: `tower_governor`'s
`per_second(n)` configures "one token per *n seconds*", not "n per second" —
the limiter was effectively 1 req/1000 s with a burst. Fixed by configuring
the replenish interval (`per_nanosecond(1e9 / rps)`); regression-tested.

## 7. Deployment/ops (tracked, mostly mechanical)

- Postgres for the production log (SQLite + volume is fine for staging).
- CDN in front of `/tile/*` and `/checkpoint` (immutable tiles cache
  forever; checkpoint no-cache). The origin then only serves `/add` and
  `/vindex/*`.
- Witness recruitment: 3–5 independent orgs (prefix.dev, Anaconda,
  Quansight, QuantStack + existing C2SP witnesses once interop is proven),
  quorum 3.
- Alerting: monitor violations → webhook/status page; log health: pending
  count growth, checkpoint age, witness cosign failure rate.
- Bootstrap plan: **done** — `siglog-import` bulk-builds tree + tiles +
  bundles + vindex + checkpoint in one pass (byte-identical to incremental
  integration; measured 5,497 entries/s locally, 200k entries → 1,571
  objects). `conda-log-ingest --jsonl-out` converts repodata to its input.
  A `--epoch-note` marker entry records what the bootstrap represents.
  Run as a one-off Fly machine holding the volume (runbook in README).
  Ongoing sync after bootstrap: scheduled job (GitHub Actions cron is fine)
  diffing repodata against the log and submitting deltas via `POST /add`;
  the publish-time hook in channel infrastructure is the end state.
