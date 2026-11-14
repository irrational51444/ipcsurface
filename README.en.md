# ipcsurface

[![version](docs/badges/version.svg)](https://github.com/irrational51444/ipcsurface/releases)
[![tests](docs/badges/tests.svg)](tests/test_ipcsurface.py)
[![python](docs/badges/python.svg)](pyproject.toml)
[![license](docs/badges/license.svg)](LICENSE)

**Squash an Electron app's capability surface onto one page.** Zero dependencies beyond Python. Current **0.161.0**.

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

## What the report can answer

The report is layered. Each layer answers one question and states what it cannot answer.
**The layers do not add up** — one name can be recovered and also seen at runtime.

### 1. How many doors does this building have? -> channel list

Obsidian: **47 channels**. Recovered 47, literal 0, enumerated 0, harvested candidates 221.

### 2. What is behind each door? -> dangerous APIs

**116 dangerous APIs**, each with a provenance tier. Only **25 are hard findings**;
the rest you neither trust nor need to verify.

### 3. Can an outside hand reach behind the door? -> three taint layers

- **L1 zero-hop**: the argument *is* the IPC parameter. **5 channels** on Obsidian.
- **L2 one hop**: through `path.join` / `resolve`. **3 channels**, each with a verdict —
  anchored / escapes / root-is-a-parameter / root-is-a-local / root unknown.
- **L3 cross-function**: into another function in the same file. **0 channels**.
  This layer has a **hard cap of two hops**. Depth 3 was tried: +67% runtime, zero
  change in results, so it stays at 2. Chains the cap cuts off are counted separately —
  the report says "the depth cap cut off N chains" and says it even when N=0
  ("this package needs no third hop"). obsidian and ACLOS: **0** each.

### 4. Is the value stored and reused next round? -> state fields

`C.icon = i` — the parameter is written into a module-level field, and a few statements
later `rmSync` uses it to delete a file. **9 channels** on Obsidian. Both ends are
reported: the write site, every read site in the same body, whether each read is a read
or a `delete`, whether it happens before or after the write, and which call it sits in.

**This layer stops there.** A state field lives across requests; knowing what is inside
it on the next read needs heap modelling — not done, and not pretended.

### 5. How is the code stitched together? -> block scope + module graph

- **Block scope**: minified bundles reuse `v` hundreds of times, so regex-based rooting
  always lands on the wrong assignment. Following `{}` parentage gives visibility.
  Obsidian's `F.join(v, C.icon)` resolves `v` to `app.getPath("userData")` — two L2 rows
  moved from "root unknown" to anchored.
- **Destructuring rename**: after `const {ipcMain: a} = require("electron")` the word
  `ipcMain` never appears again. Matching the literal alone reported **zero channels**
  for ACLOS; it now reports 285.
- **Module graph**: `app.js` **195 modules / 304 dependency edges**; `quicklook.js`
  166 / 269; `main.js` has no module table (single-file bundle).

**The module graph is fit for purpose, not omniscient**: it answers "who requires whom",
not dynamic `require` (`n(var)`, `n("a"+b)` are dropped).

**Carrying values across modules resolves 0 times on Obsidian.** `app.js` has 28
`n(id).name` uses, `quicklook.js` has 20, and not one matches an export entry — because
`e.exports = a` (whole-object assignment) dominates, so members hang off `a.X` rather
than the module body's `t.X`. Following that needs object-shape analysis, a different
order of magnitude. The report prints the resolved/total pair; 0 is 0.

**Cross-module handlers are 0 for 0 across 8 real apps on this machine.** The form
`ipcMain.handle('x', mod.fn)` does not appear once in ~36k JS files; the only non-inline
handlers are `this.onLogEvent`-style class methods (3 of them), whose method names are
now followed into the method body.

**How an export gets recognised** (added after 0.139):

- four shapes: `t.X = ...`, `t["X"] = ...`, `e.exports.X = ...`, `e.exports = { X: ... }`,
  plus the `const e = exports; e.X = ...` receiver alias and ESM's
  `export function x` / `export { x }`;
- when the name is a variable, it is computed first: `const K = "file:save"; exports[K]`
  resolves, `"file" + "save"` resolves, `exports[getName()]` does not;
- when the name comes from a config table it is enumerated: an array literal driving a
  `for...of` loop, and object-literal keys via `for...in` or `Object.keys(M).forEach`.
  If the array or object contains a variable, a spread or a call, the whole thing is
  dropped — reporting half of it looks complete and silently loses entries.

obsidian measured: `app.js` **73** export entries, `quicklook.js` **51**.

**Following one hop across files** (after 0.140): `h = require("./m")` then
`handle("x", h.save)` follows into the target function body; the bare name from
`import { save } from "./m"` works the same way; a pure re-export
`e.exports.save = require("./impl").save` follows a second hop.
`wrap(require("./impl").save)` is **not** followed — that is an expression, not a re-export.

On the real packages here these paths **fire zero times**; the capability is held down
by 8 synthetic cases. The real packages are still waiting.

### Beyond the five questions


### Capability surface beyond IPC channels

`attack_surface` watches six faces: `shell-open`, `exec-js`, `permission-handler`,
`custom-protocol`, `deep-link`, `webview`. Each carries an argument strength tier —
literal value vs live value that could come from outside.

### Dual-engine precise scan (opt-in)

`--precise` redoes the walk with tree-sitter: cross-file `require`, class-method
following, loop enumeration (`for (const x of [...]) ipcMain.on(x)` expands). The
zero-dependency default is unchanged; install the extra to enable it:

```bash
pip install 'ipcsurface[precise]'
python ipcsurface.py app.asar --precise -o report.md
```

### Runtime probe alignment

`probe/run.js` launches a real Electron fixture and reads the channels registered at
runtime, then reconciles against the static scan. Run on a local VM (Ubuntu 26.10 +
xvfb + Electron): 7 runtime channels, 5 statically recognized, 71% total — and **the
5 app-written channels align 5/5**, the 2 misses being Electron/Node built-ins. This
is now a CI job (alignment below the gate fails the build).

### Sink provenance tier per dangerous API

`channel_sink_tiers` tags every reported dangerous API: direct / name-confirmed /
same-file chain / ambiguous-name borrow / AST-only borrow. `channel_sink_evidence`
adds the receipt for each one: tier, hop count, which function names it went through,
and the location (`file:line@char-offset` — a minified bundle is often a single line,
so a bare line number tells you nothing). Hand-checked on 6 real apps:

| Provenance tier | Right | False | Precision |
| --- | --- | --- | --- |
| direct / name-confirmed / chain | 18 | 0 | 100% |
| ambiguous-name borrow | 8 | 7 | 53% |
| AST-only borrow | 1 | 3 | 25% |

**Those 18 can be cited as-is; the two borrow tiers you neither trust nor need to
verify** — their `via` column says "same-name-ambiguous", and the md report lists
the borrowed APIs by location in its own section. 24% precision is the honest number,
but the review cost is different: previously 114 rows to read one by one, now the hard
tiers are read directly and the soft ones are skipped at a glance.

The more direct the path, the higher the precision — **monotone**, and the calibration
script asserts it rather than claiming it.

### Benchmark on 6 real apps

`scripts/benchmark.py`: channel precision 100%, recall 96%; API precision 24% — that
24% is honest (shared functions over-approximate). Corpus is 6 real apps (Obsidian /
DeepSeek Harness / douyin / bilibili / vivo / ACLOS); see `docs/benchmark.md`.

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

**3. Consumers check `schema` first.** Today it is `ipcsurface/asar/38`. If it does not match, stop.

---

## What makes it checkable

Six things someone else can verify without trusting the author:

- **`content_digest`** — sha256 of the report body (minus timestamp and itself). Recompute it; a match means the report was not edited and came from this version.
- **`archive_merkle`** — per-file `path:sha256`, sorted and aggregated, so two parties can agree they analysed the same archive.
- **Both integrity digests carry a `claim` block** — `proves` is "same thing, unchanged since the digest"; `does_not_prove` says outright not `safety`, not `absence_of_backdoor`; `security_rating` is `false`. "This is not a security rating" used to live only in prose; now it is a field, and readers cannot walk past it.
- **`fingerprint`** — input sha256 + version + schema + params + channel names. Same input must give the same value; unreadable input stays `null`.
- **`refutes_if`** — per channel, what observation would prove the conclusion wrong, not what supports it.
- **Samples** — md shows two per tier, picked by name sha1 so everyone sees the same two; JSON carries `sites` (all positions) and `evidence[*].where_all`.
- **Hand-labelled ground truth** — `tests/golden/real_packages.json`, scored by
  `scripts/benchmark.py`. Current obsidian channel precision/recall **95% / 100%**,
  combined **48% / 100%** over 24 hand-checked channels. The precision denominator is
  **every reported channel**, including ones nobody has checked — so 48% is a floor,
  not the true value. douyin / bilibili / vivo / ACLOS have no hand labelling yet and
  are skipped outright: "not measured" is never printed as 0%. The exact definitions
  and how to read each number are in `docs/benchmark.md`.

- **Adversarial inventory** — `docs/adversarial.md` is written from the bypassing side:
  18 ways to disguise a channel name, tried one by one — 13 recognised, 4 not, 1
  inconclusive, each held down by `AdversarialShapeTests`. It also has a section listing
  Electron semantics that are **not verified** (handle vs on, contextBridge boundaries,
  sandboxed preload, `nodeIntegrationInSubFrames`, custom protocols); until someone
  with Electron security background checks them, none of it may be read as covered.

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

- **574 test cases**
- **67% branch coverage**, only up, never down: python scripts/coverage_check.py, standard library only
- **15 smoke items**, every CLI entry point executed; skips are announced and the summary line is computed by the script
- **Input parser fuzz**: `python scripts/fuzz_smoke.py` byte-level mutation of asar headers / PE imports; CI also runs 30 s of real atheris fuzz
- **Benchmark**: `python scripts/benchmark.py` — channel / API precision and recall (numbers in `docs/benchmark.md`)
- **Calibration**: `python scripts/calibration.py` — per-tier precision on evidence strength and sink provenance, catching tiers that do not live up to their name
- **Runtime alignment**: `python scripts/probe_align.py probe.json app.asar` — app channels must align
- **End to end**: `python scripts/e2e_check.py` — installed CLI, schema, md/json agreement, exit codes, determinism, ground-truth scoring
- **Self-check**: version, packaging metadata, schema, rule registry, docs-vs-code, clean worktree, lower bounds on the known-wrong list; --fast skips the real-app scan and smoke run (116s -> 20s, for CI; the release gate still runs everything)
- All in one command: `bash scripts/verify.sh`, which CI runs too

CI runs six jobs: `check` (Linux, gates + coverage + perf), `windows` (same gates plus Windows-specific assertions), `fuzz` (30 s atheris), `probe` (xvfb + Electron runtime alignment), `signal` (exit-code contract and SARIF), `e2e` (install and reconcile).

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

## Two examples, both actually run

### 1. A tiny range: three channels — one safe, one writes files, one runs commands

Build it yourself, no proprietary sample needed:

```bash
python scripts/make_demo_asar.py build/demo.asar
python ipcsurface.py build/demo.asar
```

![demo run](docs/img/example-demo.png)

The report says three things: `demo:ping` touches nothing; `demo:save-note` can write
a file and `demo:run` can execute a command; and for those two the **request data
reaches the dangerous parameter** — the short list you act on, not a reminder.

### 2. A real one: Obsidian's 26.8 MB `obsidian.asar`

```bash
python ipcsurface.py "/path/to/Obsidian/resources/obsidian.asar"
```

![obsidian run](docs/img/example-obsidian.png)

On the same package the name-level scan reports 19 channels reaching dangerous APIs,
the AST pass reports 22 — the difference is member calls and aliases, which
name matching cannot see. Eleven of them I verified by reading the source
(`print-to-pdf` really calls `writeFile`, `vault-move` really calls `renameSync`,
`sandbox` really reaches `rmSync`); the rest are "I see the chain, nobody confirmed it".

