# Detection benchmark

Baselines averaged over 5 seeded datasets of 50 entries at 20% prevalence (10 malicious / 40 benign).

## Easy data

| Detector | Precision | Recall | F1 | Accuracy |
|---|---|---|---|---|
| Naive SIEM rules | 100% | 100% | 100% | 100% |
| Isolation Forest (true prevalence) | 88% | 88% | 88% | 95% |
| Context-aware rules | 100% | 100% | 100% | 100% |

## Hard data

| Detector | Precision | Recall | F1 | Accuracy |
|---|---|---|---|---|
| Naive SIEM rules | 17% | 60% | 26% | 32% |
| Isolation Forest (true prevalence) | 42% | 42% | 42% | 77% |
| Context-aware rules | 88% | 80% | 83% | 94% |

_Easy data is cleanly separable by design; hard data contains benign-but-unusual and malicious-but-quiet scenarios (see src/log_generator.py)._
