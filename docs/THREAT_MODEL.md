# Threat model

solsentry is a defensive, offline static analyzer. This page states what it protects, what it
trusts, and how it can be fooled.

## What solsentry is for

A developer or auditor runs solsentry on the solc AST of *their own* (or an audited client's)
Solidity code, before deployment or in CI, to surface eight well-known bug classes early. It
reports; it never deploys, executes, or interacts with a blockchain or any network service.

## Assets

1. **The developer's machine and CI runner** — solsentry parses untrusted JSON.
2. **The integrity of the verdict** — a finding (or its absence) influences whether code ships.
3. **The integrity of the compiler used to produce fixture ASTs** — a substituted solc could
   produce ASTs that do not match the source.

## Trust boundaries and adversaries

| Boundary | Adversary | Mitigation in solsentry |
|---|---|---|
| AST JSON input (bundle, standard-JSON, bare SourceUnit) | A malicious or malformed file (e.g. from a PR) trying to crash, hang or exhaust memory in the analyzer | Input size cap and structural validation in `solast.py`; `AstFormatError` on bad shape; per-function CFG node cap (50,000); hard iteration caps in the dataflow solver and summary fixpoints; JSON is parsed with the stdlib parser only (no `eval`, no pickle, no code execution); failures are reported as exit code 2 without a traceback |
| Source paths inside an AST | Paths like `../../etc/passwd` used to make reports read other files | solsentry reads source text from the bundle; for solc standard-JSON it resolves sources only under `--source-root` |
| Compiler binary (`make fixtures`, `solsentry compile`) | A tampered solc download | SHA-256 of each pinned release checked against values pinned in `compile.py` before the binary runs; only two versions are allowed |
| Contract author vs. reviewer | A contract author who wants a bug to pass review | **Not defended.** See "Evasion" below |
| SARIF consumer (code-scanning UI) | Crafted snippets in findings | Snippets are copied source text inside JSON strings; rendering safety is the consumer's responsibility |

## Evasion (known and accepted)

solsentry is a heuristic bug finder over a single compilation unit. An author who controls the
code can hide each bug class from it, for example by: moving an external call behind a virtual
function overridden in another contract; using inline assembly; adding a guard with inverted
polarity (`if (msg.sender != owner) { ... }` counts as a guard); splitting state across
transactions; or adding an inline `solsentry-disable-line` comment. **A clean solsentry run is
not evidence that a contract is safe.** It is one input to a review, never a substitute for
one. `docs/DETECTORS.md` lists the false-negative classes per detector.

## Out of scope

- Runtime monitoring, transaction simulation, fuzzing, symbolic execution, formal verification.
- Bytecode analysis, deployed-contract scanning, or any interaction with a live chain.
- Cross-contract and economic attacks (oracle manipulation, flash-loan price attacks, MEV).

## Ethics

All fixture contracts are small, intentionally vulnerable teaching examples written for this
repository and labelled "never deploy". The demo analyzes only these local fixtures. Nothing in
this project targets a real deployed contract or third-party system.
