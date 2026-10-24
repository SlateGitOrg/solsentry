# Detectors and their soundness limits

solsentry is a *bug finder*, not a verifier. None of the eight detectors is sound (they can
miss real bugs) and none is complete (they can report non-bugs). This page states, for
each detector, exactly what is reported, where the report is anchored, which analysis
facts it relies on, and the false-positive / false-negative classes we know about. Where the
holdout evaluation (`docs/eval/holdout-first-run.md`) exposed one of these, the fixture
is cited.

Shared machinery that every detector inherits:

| Fact | How it is computed | Limit that applies to all detectors |
|---|---|---|
| Control flow | statement-level CFG per function, modifiers inlined (`src/solsentry/cfg.py`) | `&&`, `\|\|` and `?:` are not split into edges; inline assembly is one opaque node |
| Protection | dominator / post-dominator trees (`dominators.py`) | path-insensitive: a guard counts if it dominates, regardless of what it compares |
| Identity check | structural test on a gating condition (`analysis.py: is_identity_check`) | polarity is not checked; see "identity check" in `DECISIONS.md` |
| Data flow | reaching definitions (`defuse.py`), may-taint (`taint.py`) | explicit flows only; storage per variable root; parameters of every function are attacker-controlled |
| Inter-procedural | fixpoint summaries over the *internal* call graph | static resolution of `referencedDeclaration`: virtual overrides are not followed; nothing is known about external callees |
| Scope | each function analysed once, in the contract that declares it | cross-contract and cross-transaction behaviour is not modelled |

---

## reentrancy — SWC-107, CWE-841, severity high

**Reports** an external call that can transfer control (high-level call to a non-`view`
function, `call`, `delegatecall`, `try` external call, assembly `call`/`delegatecall`, or an
internal call whose callee transitively makes one) when some CFG path from it reaches a
write to a storage variable. The write may be direct, through a local `storage` pointer, or
inside an internal callee.

**Anchor:** the call expression (for helpers, the internal call in the analysed function).
Related locations list each write.

**Suppressed when** a reentrancy lock dominates the call. A lock is recognised structurally:
a check reading storage variable `L` dominates a strong write to `L`, inline (OpenZeppelin
4.x `nonReentrant`, Uniswap V2 `lock`) or inside an internal helper whose every exit
acquires it (OpenZeppelin 5.x `_nonReentrantBefore`). Writes to lock variables, constants,
immutables and storage that nothing reads are ignored.

**False negatives (by design):**
- cross-function reentrancy (re-entering a *different* function that reads the state);
- read-only reentrancy (a `view` function returning stale state to a third party);
- `transfer`/`send` (2300-gas stipend) are treated as safe;
- calls hidden behind virtual functions overridden in derived contracts;
- transient-storage (`tstore`) locks are not recognised, so such guarded code is reported (FP).

**False positives:** state writes after a call to a *trusted* contract (the analysis has no
notion of trust); writes guarded by bespoke locks that do not match the structural pattern.

## tx-origin — SWC-115, CWE-477, severity medium

**Reports** each leaf of a gating condition (`require`/`assert` argument, `if`/loop
condition) whose taint includes `tx.origin`, after splitting `&&`/`||`. Taint follows
locals, internal-call return values (e.g. `_isAuthorized()` returning `tx.origin == owner`,
holdout `GuardedVault_vuln`) and inlined modifiers.

**Anchor:** the condition leaf. Modifiers inlined into several functions yield one report.

**Not reported:** the anti-contract idiom `tx.origin == msg.sender` / `msg.sender == tx.origin`.

**False negatives:** implicit flows (`if (tx.origin == a) flag = true; ... require(flag)`),
`tx.origin` stored to storage in one transaction and checked in another.

**False positives:** `tx.origin` used in a condition for non-authorization reasons (e.g.
gas-refund heuristics).

## unchecked-call — SWC-104, CWE-252, severity medium

**Reports** `call`, `delegatecall`, `staticcall` and `send` whose boolean result is
discarded, or captured in a variable none of whose def-use successors (through copies and
boolean combinations such as `both = both && sent`) reaches a branch condition, a
`require`/`assert`, a `return`, or an argument of another call.

**Anchor:** the low-level call.

**Counts as checked (possible false negatives):** passing the flag to *any* call (the callee
may ignore it), returning it (the caller may ignore it), using it in a ternary condition.
Emitting it in an event does **not** count as checked (`Relay_vuln`).

**False negatives:** flags stored to storage and checked in a later transaction count as
unchecked (FP rather than FN); success checked but return *data* not validated (e.g.
decoding without a length check) is out of scope.

## unprotected-selfdestruct — SWC-106, CWE-284, severity high

**Reports** `selfdestruct` (Solidity or assembly) reachable in an externally callable
function — directly or via an internal helper whose every exit is not itself guarded — where
no identity check dominates the node.

**Anchor:** the `selfdestruct` call, or the internal-call site in the entry function
(`Migrator_vuln`).

**Not protection:** checks that do not compare the caller's identity against trusted data —
non-zero beneficiary (`Closable_vuln`), a pause flag (`Emergency_vuln`), a role lookup keyed by
a *parameter* (`Shutdown_vuln`).

**False negatives:** a guard compares `msg.sender` against storage that anyone can
overwrite (the guard is "present" but bypassable — that bug is reported separately by
missing-access-control when the storage is an authorization variable); guards with the
wrong polarity.

## unprotected-delegatecall — SWC-112, CWE-829, severity high

**Reports** a Solidity-level `delegatecall` in an externally callable function whose target
address is tainted by a parameter, calldata (`CalldataRouter_vuln`) or an external call
result, with no dominating identity check.

**Anchor:** the `delegatecall`.

**False positives (holdout `Upgradeable_fixed`):** targets restricted by an allow-list
(`require(approvedFacet[facet])`) rather than by caller identity — the analysis does not
treat a membership check on the *target* as sanitising it.

**False negatives:** delegatecall inside inline assembly or inside internal helpers;
storage-held targets that an unguarded setter can change (the setter itself may be reported
by missing-access-control if the target variable is an authorization variable — usually it
is not, see `Upgradeable_vuln`).

## missing-access-control — SWC-105, CWE-284, severity high

**Reports**, in an externally callable state-changing function, (1) a write to an
*authorization variable* — any storage variable read by some identity check anywhere in
the program (`owner`, `admins`, `minters`, `_roles`, `pendingOwner`) — directly, through a
storage pointer, or via an unguarded internal helper (`TwoStepOwner_vuln`); or (2) a
`transfer`/`send`/`call{value:}` of `address(this).balance` to a caller-chosen or
`msg.sender` recipient (`Treasury_vuln`, `Payroll_vuln`). Not reported when an identity check
or a one-shot initializer flag (`require(!initialized); initialized = true;`) dominates.

**Anchor:** the write statement, internal call, or value transfer.

**False negatives (holdout `CommunityVault`, `Upgradeable_vuln`):** privileged state that is
never guarded anywhere — a fee recipient, an implementation pointer, a lone unprotected
`mint`. The detector infers privilege from existing guards; it has no specification of
intent.

**False positives (holdout `NFTMarket`):** "ownership-of-record" checks such as
`require(listings[id].seller == msg.sender)` make `listings` look like an authorization
variable, so legitimate unguarded writes (`list`, `buy`) are reported.

## integer-overflow — SWC-101, CWE-190/191, severity high

**Reports** `+ - * **`, `+= -= *=`, `++ --` on integer types in *wrapping* arithmetic (code
compiled with solc < 0.8, or inside `unchecked { }`) when an operand carries attacker taint
(`PARAM`, `VALUE`, `CALLDATA`, `EXTCALL`) and the operation is not discharged by:
- a **pre-check**: a dominating comparison whose operands mention every non-literal operand
  (`require(balance >= amount)` before `balance -= amount`), or
- a **post-check**: a post-dominating comparison relating the stored result to an operand
  (SafeMath's `c = a + b; require(c >= a)` and `require(c / a == b)`).

Arithmetic inside a check is the check and is skipped. The compiler version comes from the
bundle, else from the `pragma`.

**Anchor:** the arithmetic operation.

**False positives (holdout `FeeSplitter_vuln:12`):** no value-range reasoning — `amount -
amount * 30 / 10000` cannot underflow but is reported; a bound such as `require(x < 100)`
does not discharge `x * y`.

**False negatives:** overflow driven purely by storage or loop counters (no attacker taint);
checks that are semantically sufficient but syntactically unrelated; arithmetic in inline
assembly; a post-check that is present but wrong (e.g. compares the wrong operand) is
accepted if it mentions the result and an operand.

## timestamp-dependence — SWC-116 / SWC-120, CWE-829, severity medium (randomness) / low (equality)

**Reports**, at most once per statement, a `%` whose left operand is derived from
`block.timestamp`/`now` — directly, via locals, hashing or internal-call returns
(`CoinFlip_vuln` `_random()`) — as randomness (medium), else an `==`/`!=` comparison with a
timestamp-derived side (low).

**Anchor:** the `%` or comparison.

**Not reported:** range comparisons (`>=`, `<`) — deadlines tolerate validator drift; storing
the timestamp; hashing it into identifiers that are never reduced or compared.

**False positives (holdout `CommunityVault:54`, `CoinFlip_vuln:15`):** calendar arithmetic
(`(day + 4) % 7`) is indistinguishable from randomness; a boolean *derived* from a
timestamp-randomness value and then compared for equality is reported a second time.

**False negatives:** other weak randomness sources (`blockhash`, `block.prevrandao`,
`block.number`) are out of scope; timestamp written to storage and compared in a later
transaction.
