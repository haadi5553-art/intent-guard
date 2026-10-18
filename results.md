## Attack success rate (%), simulated agent - lower is better (mean ± sd, 5 seeds, 200 attacks per set)

| Defense | Test wording | Adaptive | Adaptive: exfil | Adaptive: delete | Adaptive: leak-in-reply | Benign task success (%) |
| --- | --- | --- | --- | --- | --- | --- |
| no defense | 89.4 ± 2.0 | 90.5 ± 2.3 | 89.8 ± 3.7 | 91.2 ± 1.7 | 91.3 ± 2.9 | 100.0 ± 0.0 |
| detector (raw) | 10.6 ± 2.8 | 49.7 ± 2.8 | 45.6 ± 3.4 | 53.0 ± 2.5 | 56.7 ± 12.2 | 100.0 ± 0.0 |
| detector + canonicalise | 9.6 ± 1.8 | 24.6 ± 1.7 | 18.4 ± 5.8 | 31.7 ± 3.8 | 22.2 ± 3.9 | 100.0 ± 0.0 |
| gate only | 7.3 ± 2.2 | 7.4 ± 1.0 | 0.0 ± 0.0 | 0.0 ± 0.0 | 91.3 ± 2.9 | 100.0 ± 0.0 |
| canary only | 54.6 ± 4.6 | 50.8 ± 3.0 | 18.6 ± 2.5 | 91.2 ± 1.7 | 31.4 ± 12.8 | 100.0 ± 0.0 |
| gate + canary | 1.4 ± 1.1 | 2.5 ± 1.0 | 0.0 ± 0.0 | 0.0 ± 0.0 | 31.4 ± 12.8 | 100.0 ± 0.0 |
| all three | 0.0 ± 0.0 | 0.5 ± 0.3 | 0.0 ± 0.0 | 0.0 ± 0.0 | 6.1 ± 3.4 | 100.0 ± 0.0 |

## Detector, document level (mean ± sd over 5 seeds; negatives = benign emails incl. hard benign)

| Detector | Attack set | Precision % | Recall % | F1 % | False positive rate % |
| --- | --- | --- | --- | --- | --- |
| raw | Tool-abuse, held-out wording | 100.0 ± 0.0 | 88.3 ± 2.9 | 93.8 ± 1.6 | 0.0 ± 0.0 |
| raw | Tool-abuse, adaptive | 100.0 ± 0.0 | 45.0 ± 1.3 | 62.1 ± 1.3 | 0.0 ± 0.0 |
| raw | BIPIA public hold-out (test attacks on test emails) | 100.0 ± 0.0 | 32.1 ± 2.3 | 48.6 ± 2.6 | 0.0 ± 0.0 |
| + canonicalise | Tool-abuse, held-out wording | 100.0 ± 0.0 | 89.7 ± 2.1 | 94.6 ± 1.1 | 0.0 ± 0.0 |
| + canonicalise | Tool-abuse, adaptive | 100.0 ± 0.0 | 73.8 ± 2.6 | 84.9 ± 1.8 | 0.0 ± 0.0 |
| + canonicalise | BIPIA public hold-out (test attacks on test emails) | 100.0 ± 0.0 | 33.3 ± 2.6 | 49.9 ± 2.9 | 0.0 ± 0.0 |

## Detector recall (%) by adaptive style (tool-abuse adaptive set)

| Style | raw | + canonicalise |
| --- | --- | --- |
| soft | 89 | 91 |
| leet | 0 | 37 |
| terse | 86 | 87 |
| ps | 85 | 85 |
| base64 | 0 | 54 |
| rot13 | 6 | 88 |
| reverse | 38 | 97 |
| nospace | 45 | 47 |

## Detector recall (%) by BIPIA test attack category (raw vs + canonicalise)

| Category | raw | + canonicalise |
| --- | --- | --- |
| Base Encoding | 37 | 35 |
| Business Intelligence | 8 | 11 |
| Conversational Agent | 1 | 1 |
| Emoji Substitution | 34 | 38 |
| Entertainment | 79 | 77 |
| Information Dissemination | 51 | 51 |
| Language Translation | 35 | 35 |
| Marketing & Advertising | 54 | 57 |
| Misinformation & Propaganda | 67 | 67 |
| Research Assistance | 9 | 12 |
| Reverse Text | 25 | 30 |
| Scams & Fraud | 63 | 62 |
| Sentiment Analysis | 7 | 7 |
| Substitution Ciphers | 27 | 29 |
| Task Automation | 0 | 0 |

## Latency (defense code only; excludes LLM time)

- Detector raw: 4.8 ms per email; + canonicalise: 7.7 ms per email (3 emails per scenario).
- Gate + canary: 0.002 ms per scenario.
