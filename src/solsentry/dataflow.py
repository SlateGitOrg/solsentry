"""A generic forward worklist solver for monotone dataflow problems over a :class:`Cfg`.

Facts must be immutable values compared with ``==``. The solver iterates in reverse
post-order and re-queues successors whose input changed, so it terminates for any lattice
of finite height with a monotone transfer function. ``max_iterations`` guards against
non-monotone transfer functions supplied by mistake.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Callable
from dataclasses import dataclass

from solsentry.cfg import Cfg, CfgNode
from solsentry.errors import SolsentryError


@dataclass
class DataflowResult[F]:
    inputs: dict[int, F]
    outputs: dict[int, F]
    iterations: int


def solve_forward[F](
    cfg: Cfg,
    entry_fact: F,
    bottom: F,
    transfer: Callable[[CfgNode, F], F],
    join: Callable[[F, F], F],
    max_iterations: int = 100_000,
) -> DataflowResult[F]:
    order = cfg.reverse_postorder()
    rank = {node_id: index for index, node_id in enumerate(order)}
    inputs: dict[int, F] = dict.fromkeys(cfg.nodes, bottom)
    outputs: dict[int, F] = dict.fromkeys(cfg.nodes, bottom)
    inputs[cfg.entry] = entry_fact
    worklist = deque(order)
    queued = set(order)
    iterations = 0
    while worklist:
        iterations += 1
        if iterations > max_iterations:
            raise SolsentryError(f"dataflow did not converge for {cfg.function.qualified_name}")
        node_id = worklist.popleft()
        queued.discard(node_id)
        node = cfg.nodes[node_id]
        if node_id != cfg.entry:
            fact = bottom
            for pred in cfg.predecessors(node_id):
                fact = join(fact, outputs[pred])
            inputs[node_id] = fact
        out = transfer(node, inputs[node_id])
        if out != outputs[node_id]:
            outputs[node_id] = out
            for succ in sorted(cfg.successors(node_id), key=lambda n: rank.get(n, len(rank))):
                if succ not in queued:
                    worklist.append(succ)
                    queued.add(succ)
    return DataflowResult(inputs, outputs, iterations)
