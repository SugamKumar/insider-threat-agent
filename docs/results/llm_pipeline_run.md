# LLM pipeline run

- Model: groq/openai/gpt-oss-120b, analysed in batches of 2
- Data: hard mode, 10 entries (5 malicious, 5 benign), `python src/log_generator.py --difficulty hard --suspicious 5 --normal 5 --seed 42`
- All defenses on. Critical, High and Medium count as flagged; Low counts as benign.

## Scores on this dataset

| Detector | Precision | Recall | F1 | Accuracy |
|---|---|---|---|---|
| Naive SIEM-style rules | 43% | 60% | 50% | 40% |
| Isolation Forest | 40% | 40% | 40% | 40% |
| LLM agents | 80% | 80% | 80% | 80% |
| Context-aware rules (upper bound) | 100% | 80% | 89% | 90% |

## Per-entry results

| Employee | Scenario (hidden from agents) | Truth | Agent rating | Technique | Evidence score | Correct |
|---|---|---|---|---|---|---|
| EMP-4552 | classic suspicious | malicious | Critical | T1567 | 7 | yes |
| EMP-3657 | malicious low and slow email | malicious | Low | None | 2 | no |
| EMP-9654 | malicious forged ticket | malicious | High | T1074.002 | 7 | yes |
| EMP-0750 | routine | benign | Low | None | 0 | yes |
| EMP-0520 | malicious cross department access | malicious | Medium | T1021.002 | 3 | yes |
| EMP-5635 | benign quarter end export | benign | Low | T1213 | 2 | yes |
| EMP-4741 | benign approved maintenance | benign | Low | T1078 | 1 | yes |
| EMP-0434 | malicious business hours usb | malicious | High | T1052.001 | 4 | yes |
| EMP-5514 | benign approved maintenance | benign | Low | None | 1 | yes |
| EMP-4803 | benign business travel | benign | Medium | T1078 | 2 | no |

## Notes

- The agents caught the forged change ticket (the ticket lookup showed it was not in the registry), the cross-department access to a sensitive share and the business-hours USB copy. None of these stand out by time or volume.
- They cleared both approved after-hours maintenance entries and the quarter-end Finance export, which the naive rules flag.
- Missed: a 4.3 MB email to a personal domain. The Finance volume baseline was inflated by a large quarter-end export, so the transfer looked small, and the model did not weigh the destination. Its evidence score of 2 is below the guardrail threshold, so it was not routed to review. This is the quiet-insider case described in the threat model.
- False positive: VPN access from an unusual location during business travel, rated Medium.
- 10 entries is a small sample. Treat these numbers as a first measurement, not a stable estimate.
