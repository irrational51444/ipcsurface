# ipcsurface

[![version](docs/badges/version.svg)](https://github.com/irrational51444/ipcsurface/releases)
[![tests](docs/badges/tests.svg)](tests/test_ipcsurface.py)
[![python](docs/badges/python.svg)](pyproject.toml)
[![license](docs/badges/license.svg)](LICENSE)

**Squash an Electron app's capability surface onto one page.** Zero dependencies beyond Python. Current **0.72.0**.

Point it at an `.asar` archive (or a REA Evidence JSON, or a dll/exe) and get a report: how many IPC channels exist, which names are literal, which were recovered by deobfuscation, which only look like channels — plus **how far you can trust it, and how to check it yourself**.

[中文 README](README.md) · [Changelog](CHANGELOG.md) · [Fixtures](examples/README.md) · [Known wrong](docs/known-wrong.md)

---

## One real run

A real Electron app on this machine: 441 MB, 22,102 files, 4.7 s.

![Real app scan](docs/img/case-real-scan.png)

One command for the report, then reconcile against hand-labelled ground truth (recall / precision / coverage):

![Fixture and ground truth](docs/img/case-fixture-run.png)

Three gates, same set locally and in CI:

![Gates](docs/img/case-gates.png)

---

## Why "number of channels" is not the answer

Statements in one report do not carry the same weight. From that real report:

| Tier | Count | Proves | Does not prove |
| --- | --- | --- | --- |
| Literal names | 11 | Written verbatim; `file:line` lets you check the source | Only covers literal spellings |
| Recovered names | 84 | Pulled out of string pools / constant tables, provenance is in source | Found ≠ actually a channel |
| Computed names | 0 | There is a call here, the name is not literal | What the name is |
| Harvested candidates | 221 (51 written by the app) | These strings look like channel names | Looking like one is not being one |
| Unseen | unknown | Nothing | This path cannot see it |

**Never sum the tiers.** One name can be both recovered and seen at runtime; both rows count it. The report is a map, not a verdict.

---

## Install

```bash
pip install .
python ipcsurface.py app.asar      # or run it in place
```

Python 3.9+, no third-party packages.

## One-minute tour

```bash
python ipcsurface.py app.asar -o report.md
python ipcsurface.py app.asar --format json -o r.json
python ipcsurface.py app.asar --baseline last.json
python ipcsurface.py app.asar --fail-on high     # exit 2 when something high shows up
```

Try the bundled fixtures:

```bash
cd examples && bash build.sh
python ipcsurface.py build/static-asar.asar -o report.md
```

---

## Three rules of the report

**1. Unknown is `null`, never `0`.** Not seeing something is not the same as it not being there.

**2. Evidence records provenance, never a verdict.** Every channel carries where the name came from, how strong it is, and **what observations would refute it**. Strength orders review effort, not probability.

**3. Consumers check `schema` first.** Today it is `ipcsurface/asar/10`. If it does not match, stop.

---

## What makes it checkable

Six things someone else can verify without trusting the author:

- **`content_digest`** — sha256 of the report body (minus timestamp and itself). Recompute it; a match means the report was not edited and came from this version.
- **`archive_merkle`** — per-file `path:sha256`, sorted and aggregated, so two parties can agree they analysed the same archive. Not a security rating.
- **`fingerprint`** — input sha256 + version + schema + params + channel names. Same input must give the same value; unreadable input stays `null`.
- **`refutes_if`** — per channel, what observation would prove the conclusion wrong, not what supports it.
- **Samples** — md shows two per tier, picked by name sha1 so everyone sees the same two; JSON carries `sites` (all positions) and `evidence[*].where_all`.
- **Hand-labelled ground truth** — `tests/golden/ground_truth.json`, scored by `scripts/ground_truth_check.py`. Current average coverage **0.88**; the gap is `'ledger:' + op` style runtime-composed names, listed under `known_unreachable`.

Corroboration levels (`strong` / `medium` / `weak-same-line` / `weak-near-line`) exist in code and tests, but **the runtime side does not report positions yet, so real output is always `unknown`** — stated plainly instead of pretending.

---

## Exit codes

| Code | Meaning | What to do |
| --- | --- | --- |
| 0 | Success, no gate triggered | Durability is in the `kind:` line on stderr |
| 1 | Bad input | Fix the input |
| 2 | `--fail-on` threshold hit | Read the suspicious items |
| 3 | The tool crashed | File an issue |
| 4 | Written but not durable (directory fsync failed) | **The file is already new; do not roll back** |

The release scripts use their own set: `0` ok, `1` guard red or release exists, `2` guard unknown, `3` script error. **Non-zero does not mean failure.**

---

## Write reliability and crash leftovers

Reports are all-or-nothing: temp file in the same directory, `fsync`, byte check, then `os.replace`. What you read at the agreed path is always a complete report.

- Directory fsync failure is not a write failure; `durable` is tri-state (`yes` / `no` / `unknown`), `unknown` on Windows, exit 0.
- Replace-under-lock reports `replace_failed`, keeps the payload in `.failed`, leaves the old report alone.
- Leftovers from a crash are inspected with `python ipcsurface.py --recover out.md`, which reports facts only: no automatic restore. When the target is missing the comparison table degrades into a copy list rather than a half table.
- The "over a year" threshold for clock-forward is a heuristic; normal old files land there too.

## Machine-readable error kinds

Input: `file_missing`, `empty_input`, `encoding_invalid`, `json_truncated`, `json_malformed`, `shape_invalid`, `depth_exceeded`.

Output: `disk_full`, `permission_denied`, `short_write`, `replace_failed`, `symlink_target`, `write_failed`, `invalid_json_output`.

---

## How quality is held

- **226 test cases**, standard library only
- **15 smoke items**, every CLI entry point executed; skips are announced and the summary line is computed by the script
- **End to end**: `python scripts/e2e_check.py` — installed CLI, schema, md/json agreement, exit codes, determinism, ground-truth scoring
- **Self-check**: version, packaging metadata, schema, rule registry, docs-vs-code, clean worktree, lower bounds on the known-wrong list
- All three in one command: `bash scripts/verify.sh`, which CI runs too

CI runs four jobs: `check` (Linux), `windows` (same gates plus Windows-specific assertions), `signal` (exit-code contract and SARIF), `e2e` (install and reconcile).

Releases are scripted: `check_release_tag.py` verifies the tagged commit is CI-green (`0` green / `1` red / `2` unknown) and `make_release.py` publishes only after the guard passes (`3` means the script itself failed). Both scripts have their own tests.

---

## Known wrong

Concatenated names are invisible, look-alike strings produce false positives, obfuscator traces are leads only — catalogued in [docs/known-wrong.md](docs/known-wrong.md) under "unseen / will misfire / not to be used as a verdict".

The list has mechanical lower bounds (fixed columns, at least eight symptoms, version lock). **Content is judgement; the self-check can only prove it has not decayed into an empty shell.**

## Known limits

- String-level scan, no syntax tree; concatenated or computed names stay invisible. Use REA Evidence for precision.
- Sandboxes, native modules, runtime-wired channels are invisible statically.
- Windows directory fsync is unavailable, `durable` can only be `unknown` — asserted by the `windows` job. Read-only volumes remain untested.
- `adv-asar.asar` is a hand-made adversarial fixture with no build script; every other fixture is reproducible.
- Scale and performance assertions run on the reproducible `realish.asar` (3042 files, 12 channels, < 8 s), not on the author's 441 MB app.

---

## Licence

MIT — see [LICENSE](LICENSE).
