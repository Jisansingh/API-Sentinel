# API Sentinel benchmark

Synthetic dataset: 2643 records, 90 labelled instances (5 per scenario), seed 20260105. Ownership context supported by this build: False.

## Overall (instance x detection type)

TP 20  FP 25  TN 285  FN 25  |  precision 0.44  recall 0.44  F1 0.44  FPR 0.08

## Per detection type

| type | TP | FP | TN | FN | precision | recall | F1 | FPR |
|---|---|---|---|---|---|---|---|---|
| scraping | 10 | 20 | 50 | 5 | 0.33 | 0.67 | 0.44 | 0.29 |
| bola_enumeration | 5 | 0 | 80 | 5 | 1.00 | 0.50 | 0.67 | 0.00 |
| bola | 0 | 0 | 80 | 10 | n/a | 0.00 | n/a | 0.00 |
| token_replay | 5 | 5 | 75 | 5 | 0.50 | 0.50 | 0.50 | 0.06 |

## Tuning set (in-sample)

TP 15  FP 15  TN 170  FN 15  |  precision 0.50  recall 0.50  F1 0.50  FPR 0.08

## Holdout set (not tuned on)

TP 5  FP 10  TN 115  FN 10  |  precision 0.33  recall 0.33  F1 0.33  FPR 0.08

## Per scenario (H = holdout)

| scenario | expected | detection rate | false-alert rate |
|---|---|---|---|
| normal_browse | (none) | n/a | 0.00 |
| scraping_bulk | scraping | 1.00 | 0.00 |
| scraping_low_slow | scraping | 0.00 | 0.00 |
| bola_enumeration | bola, bola_enumeration | 0.50 | 0.00 |
| bola_unauthorized_read | bola | 0.00 | 0.00 |
| token_replay | token_replay | 1.00 | 0.00 |
| legit_high_volume | (none) | n/a | 1.00 |
| repeated_small_set | (none) | n/a | 1.00 |
| roaming_user | (none) | n/a | 1.00 |
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

precision 0.50  recall 1.00  predicted [['GET', '/docs'], ['GET', '/openapi.json'], ['GET', '/shop/admin/stats'], ['GET', '/shop/internal/export']]  false positives [['GET', '/docs'], ['GET', '/openapi.json']]  missed []

Unattributed alerts (counted as FP): 0

## Timings (non-deterministic)

```
{
 "note": "wall-clock on this machine; varies run to run",
 "python": "3.14.5",
 "scan_ms": {
  "median_ms": 71.46,
  "max_ms": 72.52
 },
 "shadow_apis_ms": {
  "median_ms": 16.68,
  "max_ms": 17.53
 },
 "analysis_only_ms": {
  "median_ms": 72.88,
  "max_ms": 77.04
 }
}
```
