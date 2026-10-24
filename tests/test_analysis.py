"""Taint, summaries and guard/lock inference."""

from __future__ import annotations

from solsentry.analysis import ProgramAnalysis
from solsentry.cfg import NodeKind
from solsentry.taint import ORIGIN, PARAM, SENDER, STATE, TIMESTAMP, ReturnSummary
from tests.conftest import analysis, function_analysis, program


def _summary(relative: str, qualified: str) -> object:
    fa = function_analysis(relative, qualified)
    return fa.owner.summary(fa.function.id)


def test_return_summaries_capture_magic_sources() -> None:
    origin = _summary("holdout/tx-origin/GuardedVault_vuln", "GuardedVault._isAuthorized")
    assert ORIGIN in origin.returns.labels  # type: ignore[attr-defined]
    rand = _summary("holdout/timestamp-dependence/CoinFlip_vuln", "CoinFlip._random")
    assert TIMESTAMP in rand.returns.labels  # type: ignore[attr-defined]
    sender = _summary("dev/missing-access-control/Treasury_fixed", "Treasury._msgSender")
    assert sender.returns.labels == frozenset({SENDER})  # type: ignore[attr-defined]


def test_return_summary_argument_dependencies() -> None:
    add = _summary("dev/integer-overflow/BatchToken_fixed", "SafeMath.add")
    assert add.returns.deps == frozenset({0, 1})  # type: ignore[attr-defined]
    summary = ReturnSummary(frozenset({1}), frozenset({STATE}))
    assert summary.apply([frozenset({"A"}), frozenset({"B"})]) == {"B", STATE}
    assert summary.apply([]) == {STATE}
    assert summary == ReturnSummary(frozenset({1}), frozenset({STATE}))
    assert summary != "other"
    assert hash(summary) == hash(ReturnSummary(frozenset({1}), frozenset({STATE})))


def test_taint_flows_through_locals_and_hashes() -> None:
    fa = function_analysis("dev/timestamp-dependence/Raffle_vuln", "Raffle.draw")
    winner_node = next(n for n in fa.cfg if "winner = players" in fa.cfg.describe(n))
    seed = next(
        d
        for d in fa.program.index.nodes.values()
        if d.get("nodeType") == "VariableDeclaration" and d.get("name") == "seed"
    )
    assert TIMESTAMP in fa.taint.env_in(winner_node.id)[int(seed["id"])]


def test_parameters_are_attacker_controlled() -> None:
    fa = function_analysis("dev/unprotected-delegatecall/Executor_vuln", "Executor.exec")
    exit_env = fa.taint.env_in(fa.cfg.exit)
    target = int(fa.function.parameters[0]["id"])
    assert exit_env[target] == frozenset({PARAM})


def test_effect_summaries_are_transitive() -> None:
    pay = _summary("dev/reentrancy/Escrow_vuln", "Escrow._pay")
    assert pay.reentrant_call  # type: ignore[attr-defined]
    destroy = _summary("holdout/unprotected-selfdestruct/Migrator_vuln", "Migrator._destroy")
    assert destroy.selfdestruct  # type: ignore[attr-defined]
    transfer = _summary(
        "holdout/missing-access-control/TwoStepOwner_vuln", "TwoStepOwner._transferOwnership"
    )
    names = {
        program("holdout/missing-access-control/TwoStepOwner_vuln").state_vars[v].name
        for v in transfer.writes
    }  # type: ignore[attr-defined]
    assert names == {"owner", "pendingOwner"}


def test_identity_guards_modifier_and_helper_forms() -> None:
    ownable = function_analysis(
        "dev/missing-access-control/Ownable_fixed", "Ownable.transferOwnership"
    )
    write = next(n for n in ownable.cfg if "owner = next" in ownable.cfg.describe(n))
    assert ownable.identity_protected(write.id)
    treasury = function_analysis("dev/missing-access-control/Treasury_fixed", "Treasury.sweep")
    assert any(check.kind == "call" for check in treasury.guards.identity)
    check_owner = _summary("dev/missing-access-control/Treasury_fixed", "Treasury._checkOwner")
    assert check_owner.sender_guarded  # type: ignore[attr-defined]
    role = function_analysis(
        "holdout/unprotected-selfdestruct/Emergency_fixed", "Emergency.emergencyStop"
    )
    assert role.guards.identity
    literal = function_analysis(
        "dev/integer-overflow/UncheckedVault_vuln", "UncheckedVault.mintShares"
    )
    assert literal.guards.identity  # msg.sender == address(0x1234)


def test_non_identity_checks_are_not_guards() -> None:
    closable = function_analysis("dev/unprotected-selfdestruct/Closable_vuln", "Closable.close")
    assert closable.guards.identity == []
    shutdown = function_analysis("dev/unprotected-selfdestruct/Shutdown_vuln", "Shutdown.shutdown")
    assert shutdown.guards.identity == []  # admins[caller]: identity supplied by the caller
    origin_idiom = function_analysis("dev/tx-origin/OriginModifier_fixed", "OriginModifier.setFee")
    conds = [c for c in origin_idiom.guards.identity if c.cond is not None]
    assert len(conds) == 1  # msg.sender == admin, but not tx.origin == msg.sender


def test_branch_guard_protects_only_its_branch() -> None:
    fa = function_analysis("holdout/tx-origin/Pausable_fixed", "Pausable.togglePause")
    (check,) = fa.guards.identity
    assert check.kind == "branch"
    write = next(n for n in fa.cfg if "paused = !paused" in fa.cfg.describe(n))
    assert fa.identity_protected(write.id)
    assert not fa.identity_protected(fa.cfg.exit)


def test_lock_detection_inline_and_helper() -> None:
    inline = function_analysis("dev/reentrancy/RewardPool_fixed", "RewardPool.claim")
    names = {inline.program.state_vars[v].name for v in inline.lock_vars()}
    assert names == {"_status"}
    helper = function_analysis("dev/reentrancy/Escrow_fixed", "Escrow.release")
    call = next(n for n in helper.cfg if "_pay(" in helper.cfg.describe(n))
    assert helper.lock_protected(call.id)
    enter = _summary("dev/reentrancy/Escrow_fixed", "Escrow._enter")
    assert enter.locks  # type: ignore[attr-defined]
    uniswap = function_analysis("holdout/reentrancy/Staking_fixed", "Staking.unstake")
    assert uniswap.lock_vars()


def test_initializer_flag_is_recognised() -> None:
    fa = function_analysis(
        "dev/missing-access-control/Initializable_fixed", "Initializable.initialize"
    )
    write = next(n for n in fa.cfg if "admin = firstAdmin" in fa.cfg.describe(n))
    assert fa.initializer_protected(write.id)
    assert not fa.identity_protected(write.id)


def test_auth_vars_and_reads(features: ProgramAnalysis) -> None:
    pa = analysis("dev/missing-access-control/Ownable_vuln")
    names = {pa.program.state_vars[v].name for v in pa.auth_vars()}
    assert names == {"owner"}
    owner = next(v.id for v in features.program.state_vars.values() if v.name == "owner")
    assert owner in features.read_anywhere
    assert features.summary(-1).writes == frozenset()


def test_assembly_effects(features: ProgramAnalysis) -> None:
    fa = next(f for f in features.functions.values() if f.function.name == "asmWrite")
    asm = next(n for n in fa.cfg if n.kind is NodeKind.ASSEMBLY)
    assert "add" in fa.asm_builtins[asm.id]
    writes = fa.effects[asm.id].writes
    assert writes and all("ASM" in w.extra_labels for w in writes)
    destroy = next(f for f in features.functions.values() if f.function.name == "asmDestroy")
    assert features.summary(destroy.function.id).selfdestruct
