# ipcsurface

[![version](docs/badges/version.svg)](https://github.com/irrational51444/ipcsurface/releases)
[![tests](docs/badges/tests.svg)](tests/test_ipcsurface.py)
[![python](docs/badges/python.svg)](pyproject.toml)
[![license](docs/badges/license.svg)](LICENSE)

**Squash an Electron app's capability surface onto one page.** Zero dependencies beyond Python. Current **0.81.0**.

Point it at an `.asar` archive (or a REA Evidence JSON, or a dll/exe) and get a report: how many IPC channels exist, which names are literal, which were recovered by deobfuscation, which only look like channels — plus **how far you can trust it, and how to check it yourself**.

[中文 README](README.md) · [Changelog](CHANGELOG.md) · [Fixtures](examples/README.md) · [Known wrong](docs/known-wrong.md)

---

## One real run

A real Electron app on this machine: 441 MB, 22,102 files, 5.0 s.

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

**How good are those 221 candidates?** Grade first, then talk about precision. Grading uses only checkable facts (is it a channel name, does it live in an IPC-mentioning file, how many share its prefix) — no semantic guessing:

| Grade | Real app | Meaning |
| --- | --- | --- |
| channel | 41 | matches a statically seen channel name; nothing left to guess |
| near-ipc | 10 | sits in a file that mentions IPC, worth reading first |
| clustered | 89 | looks like a name table (`tool`, `js` are the biggest prefixes) |
| stray | 81 | appears only elsewhere; most likely noise |

**Manual triage drops from 221 to 51** (top two grades); the other 170 are counted but collapsed until `--all`. Then precision:

- **Fixtures** (python scripts/harvest_precision.py): 17 candidates, 17 are real channel names, precision **1.00** — but the fixtures are mine and tiny.
- **The real app**: of 221 candidates, 41 are also statically seen channel names (same thing, two paths); the remaining **180 are lone**. Of those, only 12 appear in files that mention IPC, **0** sit next to a call (they live in name tables), 168 appear only elsewhere; 96 cluster by prefix (`tool=16`, `js=15`), 84 are scattered.
- **Precision: unknown.** Those 180 have not been hand-checked, and inventing a number would be worse than leaving it out.

One tier is missing from that table because **this app has none**: enumerated names (`enumerated`). When the value set is a literal array and the assembly is literals plus parameters, `for (const op of OPS) ipcMain.handle(makeChannel(op))` collapses into three concrete names. The `dyn` fixture has exactly those three; real apps rarely write it this way.

That tier has two levels, **set by proof, not by mood**: all three checks pass (loop variable never reassigned, array never mutated, helper is a single expression) → **0.9**, the same as recovered names; one fails → **0.6**, names still listed but not to be trusted. `enum_proof.failed` records which one failed.

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

**3. Consumers check `schema` first.** Today it is `ipcsurface/asar/14`. If it does not match, stop.

---

## What makes it checkable

Six things someone else can verify without trusting the author:

- **`content_digest`** — sha256 of the report body (minus timestamp and itself). Recompute it; a match means the report was not edited and came from this version.
- **`archive_merkle`** — per-file `path:sha256`, sorted and aggregated, so two parties can agree they analysed the same archive.
- **Both integrity digests carry a `claim` block** — `proves` is "same thing, unchanged since the digest"; `does_not_prove` says outright not `safety`, not `absence_of_backdoor`; `security_rating` is `false`. "This is not a security rating" used to live only in prose; now it is a field, and readers cannot walk past it.
- **`fingerprint`** — input sha256 + version + schema + params + channel names. Same input must give the same value; unreadable input stays `null`.
- **`refutes_if`** — per channel, what observation would prove the conclusion wrong, not what supports it.
- **Samples** — md shows two per tier, picked by name sha1 so everyone sees the same two; JSON carries `sites` (all positions) and `evidence[*].where_all`.
- **Hand-labelled ground truth** — `tests/golden/ground_truth.json`, scored by `scripts/ground_truth_check.py`. Current average coverage **1.00** — all four fixtures match, the three `dyn` names that used to be "cannot compute" are now enumerated (0.81.0). **That 1.00 covers four fixtures only**: 23 channels, every one written by me. `known_unreachable` is now empty; it stays honest only as long as it follows the source.

Corroboration levels (`strong` / `medium` / `weak-same-line` / `weak-near-line`) are not decoration: when the probe reports `sites` (name → `file:line`) in its JSON, the level is computed from both sides. **`unknown` only means the probe reported no position** — not computed, not "did not match". All four levels have been produced by the real CLI.

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

- Directory fsync failure is not a write failure; `durable` is tri-state (`yes` / `no` / `unknown`). `unknown` appears only when the platform has no way to flush a directory at all; exit 0.
- Replace-under-lock reports `replace_failed`, keeps the payload in `.failed`, leaves the old report alone.
- Leftovers from a crash are inspected with `python ipcsurface.py --recover out.md`, which reports facts only: no automatic restore. When the target is missing the comparison table degrades into a copy list rather than a half table.
- The "over a year" threshold for clock-forward is a heuristic; normal old files land there too.

## Machine-readable error kinds

Input: `file_missing`, `empty_input`, `encoding_invalid`, `json_truncated`, `json_malformed`, `shape_invalid`, `depth_exceeded`.

Output: `disk_full`, `permission_denied`, `short_write`, `replace_failed`, `symlink_target`, `write_failed`, `invalid_json_output`.

---

## How quality is held

- **280 test cases**, standard library only
- **15 smoke items**, every CLI entry point executed; skips are announced and the summary line is computed by the script
- **End to end**: `python scripts/e2e_check.py` — installed CLI, schema, md/json agreement, exit codes, determinism, ground-truth scoring
- **Self-check**: version, packaging metadata, schema, rule registry, docs-vs-code, clean worktree, lower bounds on the known-wrong list
- All three in one command: `bash scripts/verify.sh`, which CI runs too

CI runs four jobs: `check` (Linux), `windows` (same gates plus Windows-specific assertions), `signal` (exit-code contract and SARIF), `e2e` (install and reconcile).

Releases are scripted: `check_release_tag.py` verifies the tagged commit is CI-green (`0` green / `1` red / `2` unknown — **checks still running count as unknown**) and `make_release.py` publishes only after the guard passes (`3` means the script itself failed). Both scripts have their own tests.

---

## Known wrong

Concatenated names are mostly still invisible, look-alike strings produce false positives, obfuscator traces are leads only — catalogued in [docs/known-wrong.md](docs/known-wrong.md) under "unseen / will misfire / not to be used as a verdict".

The list has mechanical lower bounds (fixed columns, at least eight symptoms, version lock). **Content is judgement; the self-check can only prove it has not decayed into an empty shell.**

## Known limits

- String-level scan, no syntax tree. One kind of composed name is now computable: when the value set is a literal array and the assembly is literals plus parameters, it gets enumerated (`enumerated`: **0.9** when all three checks pass — loop variable never reassigned, array never mutated, helper is a single expression — and **0.6** when one fails, names still listed but not to be trusted; `enum_proof.failed` says which). Values from config, return values or loop accumulation fall back to "cannot compute". Use REA Evidence for precision.
- Sandboxes, native modules, runtime-wired channels are invisible statically.
- Windows directory flush goes through `ctypes` + `FlushFileBuffers` (the handle needs write access; read-only handles are refused). Read-only volumes and network shares are untested — there it reports `durable=no`, not `unknown`.
- `adv-asar.asar` is a hand-made adversarial fixture with no build script; every other fixture is reproducible.
- Scale and performance assertions run on the reproducible `realish.asar` (3042 files, 12 channels, < 8 s), not on the author's 441 MB app.

---

## Licence

MIT — see [LICENSE](LICENSE).
