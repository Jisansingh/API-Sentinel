# API Sentinel benchmark

Synthetic dataset: 2643 records, 90 labelled instances (5 per scenario), seed 20260105. Ownership context supported by this build: True.

## Overall (instance x detection type)

TP 35  FP 10  TN 300  FN 10  |  precision 0.78  recall 0.78  F1 0.78  FPR 0.03

## Per detection type

| type | TP | FP | TN | FN | precision | recall | F1 | FPR |
|---|---|---|---|---|---|---|---|---|
| scraping | 15 | 10 | 60 | 0 | 0.60 | 1.00 | 0.75 | 0.14 |
| bola_enumeration | 5 | 0 | 80 | 5 | 1.00 | 0.50 | 0.67 | 0.00 |
| bola | 10 | 0 | 80 | 0 | 1.00 | 1.00 | 1.00 | 0.00 |
| token_replay | 5 | 0 | 80 | 5 | 1.00 | 0.50 | 0.67 | 0.00 |

## Tuning set (in-sample)

TP 30  FP 0  TN 185  FN 0  |  precision 1.00  recall 1.00  F1 1.00  FPR 0.00

## Holdout set (not tuned on)

TP 5  FP 10  TN 115  FN 10  |  precision 0.33  recall 0.33  F1 0.33  FPR 0.08

## Per scenario (H = holdout)

| scenario | expected | detection rate | false-alert rate |
|---|---|---|---|
| normal_browse | (none) | n/a | 0.00 |
| scraping_bulk | scraping | 1.00 | 0.00 |
| scraping_low_slow | scraping | 1.00 | 0.00 |
| bola_enumeration | bola, bola_enumeration | 1.00 | 0.00 |
| bola_unauthorized_read | bola | 1.00 | 0.00 |
| token_replay | token_replay | 1.00 | 0.00 |
| legit_high_volume | (none) | n/a | 0.00 |
| repeated_small_set | (none) | n/a | 0.00 |
| roaming_user | (none) | n/a | 0.00 |
| probe_404_scanner | (none) | n/a | 0.00 |
| typo_denied_user | (none) | n/a | 0.00 |
| H h_scrape_sequential_walk | scraping | 1.00 | 0.00 |
| H h_bola_slow_probe | bola_enumeration | 0.00 | 0.00 |
| H h_replay_slow_distributed | token_replay | 0.00 | 0.00 |
| H h_nat_office | (none) | n/a | 1.00 |
| H h_partner_sync | (none) | n/a | 1.00 |
| H h_two_devices | (none) | n/a | 0.00 |
| H h_owner_reads_own | (none) | n/a | 0.00 |

## Shadow APIs

precision 1.00  recall 1.00  predicted [['GET', '/shop/admin/stats'], ['GET', '/shop/internal/export']]  false positives []  missed []

Unattributed alerts (counted as FP): 0

## Timings (non-deterministic)

```
{
 "note": "wall-clock on this machine; varies run to run",
 "python": "3.14.5",
 "scan_ms": {
  "median_ms": 157.88,
  "max_ms": 400.37
 },
 "shadow_apis_ms": {
  "median_ms": 24.64,
  "max_ms": 25.48
 },
 "analysis_only_ms": {
  "median_ms": 79.69,
  "max_ms": 80.57
 }
}
```
