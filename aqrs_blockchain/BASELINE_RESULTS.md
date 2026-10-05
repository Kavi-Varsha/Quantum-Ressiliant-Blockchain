# PQBank Baseline Results

## Date
2026-10-05

## Python Version
Python 3.13.7

## Package Versions
- cryptography==48.0.0
- dilithium-py==1.4.0
- flask==3.1.2
- flask-cors==6.0.2
- matplotlib==3.10.9
- pandas==3.0.1

## Simulation Configuration
- Transactions generated: 100
- Risk split: LOW=40, MEDIUM=40, HIGH=20
- Modes tested: ECDSA, DIL2, DIL3, DIL5, AQRS

## AQRS Results
| Mode | AQRS Score |
| --- | ---: |
| ECDSA | 1.0000 |
| DIL2 | 0.0234 |
| DIL3 | 0.0479 |
| DIL5 | 0.0465 |
| AQRS | 0.0466 |

## Performance Results
| Mode | Average Signing Time (ms) | Average Verification Time (ms) | Average Signature Size (bytes) | Throughput (TPS) |
| --- | ---: | ---: | ---: | ---: |
| ECDSA | 1.8603 | 1.5596 | 70.92 | 537.56 |
| DIL2 | 138.3110 | 120.2797 | 2544.00 | 7.23 |
| DIL3 | 71.5670 | 79.8220 | 3309.00 | 13.97 |
| DIL5 | 93.4050 | 85.1261 | 4498.00 | 10.71 |
| AQRS | 68.1130 | 74.8500 | 3295.00 | 14.68 |

## Notes
- The baseline was validated by running `python main.py` in the project root.
- The project successfully generated all six comparison plots under `plots/`.
- The results confirm the current prototype is functional and suitable as a baseline before architecture refactoring.
- The AQRS mode remains research-focused and adaptive, selecting Dilithium level based on risk classification.
- The values above are intentionally recorded as the current working baseline and should be preserved for future regression checks.
