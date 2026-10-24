# Holdout split: first evaluation (verbatim)

Produced by `uv run solsentry eval fixtures/ast/holdout --name holdout` at commit `b5bf8ee`
(detectors frozen at `1af9f94`; `b5bf8ee` only contains behaviour-neutral lint/type fixes), the
first time the analyzer ever ran on these files. Kept unchanged as the reference result.

### holdout: 41 files, 1329 source lines

| detector | TP | FP | FN | precision | recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| integer-overflow | 6 | 1 | 0 | 0.86 | 1.00 | 0.92 |
| missing-access-control | 3 | 2 | 2 | 0.60 | 0.60 | 0.60 |
| reentrancy | 6 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| timestamp-dependence | 2 | 2 | 0 | 0.50 | 1.00 | 0.67 |
| tx-origin | 2 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| unchecked-call | 3 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| unprotected-delegatecall | 2 | 1 | 0 | 0.67 | 1.00 | 0.80 |
| unprotected-selfdestruct | 2 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| **all** | 26 | 6 | 2 | 0.81 | 0.93 | 0.87 |

False positives:
- `holdout/integer-overflow/FeeSplitter_vuln.sol:12` integer-overflow
- `holdout/mixed/CommunityVault.sol:54` timestamp-dependence
- `holdout/mixed/NFTMarket.sol:39` missing-access-control
- `holdout/mixed/NFTMarket.sol:62` missing-access-control
- `holdout/timestamp-dependence/CoinFlip_vuln.sol:15` timestamp-dependence
- `holdout/unprotected-delegatecall/Upgradeable_fixed.sol:37` unprotected-delegatecall

False negatives:
- `holdout/mixed/CommunityVault.sol:70` missing-access-control
- `holdout/unprotected-delegatecall/Upgradeable_vuln.sol:21` missing-access-control
