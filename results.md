## Attack success rate (%), simulated agent - lower is better (mean ± sd, 5 seeds, 200 attacks per set)

| Defense | Test wording | Adaptive | Adaptive: exfil | Adaptive: delete | Adaptive: leak-in-reply | Benign task success (%) |
| --- | --- | --- | --- | --- | --- | --- |
| no defense | 89.4 ± 2.0 | 90.5 ± 2.3 | 89.8 ± 3.7 | 91.2 ± 1.7 | 91.3 ± 2.9 | 100.0 ± 0.0 |
| detector (raw) | 10.5 ± 2.4 | 49.2 ± 2.3 | 45.7 ± 4.4 | 52.0 ± 1.6 | 55.4 ± 11.9 | 100.0 ± 0.0 |
| detector + canonicalise | 9.3 ± 2.3 | 23.6 ± 2.1 | 17.8 ± 5.6 | 30.1 ± 4.9 | 22.2 ± 3.9 | 100.0 ± 0.0 |
| gate only | 7.3 ± 2.2 | 7.4 ± 1.0 | 0.0 ± 0.0 | 0.0 ± 0.0 | 91.3 ± 2.9 | 100.0 ± 0.0 |
| canary only | 54.6 ± 4.6 | 50.8 ± 3.0 | 18.6 ± 2.5 | 91.2 ± 1.7 | 31.4 ± 12.8 | 100.0 ± 0.0 |
| gate + canary | 1.4 ± 1.1 | 2.5 ± 1.0 | 0.0 ± 0.0 | 0.0 ± 0.0 | 31.4 ± 12.8 | 100.0 ± 0.0 |
| all three | 0.1 ± 0.2 | 0.5 ± 0.3 | 0.0 ± 0.0 | 0.0 ± 0.0 | 6.1 ± 3.4 | 100.0 ± 0.0 |

## Detector, document level (mean ± sd over 5 seeds; negatives = benign emails incl. hard benign)

| Detector | Attack set | Precision % | Recall % | F1 % | False positive rate % |
| --- | --- | --- | --- | --- | --- |
| raw | Tool-abuse, held-out wording | 100.0 ± 0.0 | 88.5 ± 2.7 | 93.9 ± 1.5 | 0.0 ± 0.0 |
| raw | Tool-abuse, adaptive | 100.0 ± 0.0 | 45.5 ± 1.1 | 62.5 ± 1.0 | 0.0 ± 0.0 |
| raw | BIPIA public hold-out (test attacks on test emails) | 100.0 ± 0.0 | 31.6 ± 2.7 | 48.0 ± 3.2 | 0.0 ± 0.0 |
| + canonicalise | Tool-abuse, held-out wording | 100.0 ± 0.0 | 89.8 ± 2.4 | 94.6 ± 1.3 | 0.0 ± 0.0 |
| + canonicalise | Tool-abuse, adaptive | 100.0 ± 0.0 | 74.9 ± 2.8 | 85.6 ± 1.9 | 0.0 ± 0.0 |
| + canonicalise | BIPIA public hold-out (test attacks on test emails) | 100.0 ± 0.0 | 33.7 ± 2.6 | 50.4 ± 2.9 | 0.0 ± 0.0 |

## Detector recall (%) by adaptive style (tool-abuse adaptive set)

| Style | raw | + canonicalise |
| --- | --- | --- |
| soft | 90 | 91 |
| leet | 0 | 44 |
| terse | 87 | 84 |
| ps | 86 | 85 |
| base64 | 0 | 56 |
| rot13 | 4 | 88 |
| reverse | 38 | 97 |
| nospace | 47 | 49 |

## Detector recall (%) by BIPIA test attack category (raw vs + canonicalise)

| Category | raw | + canonicalise |
| --- | --- | --- |
| Base Encoding | 35 | 37 |
| Business Intelligence | 8 | 12 |
| Conversational Agent | 1 | 1 |
| Emoji Substitution | 37 | 38 |
| Entertainment | 77 | 77 |
| Information Dissemination | 51 | 51 |
| Language Translation | 33 | 35 |
| Marketing & Advertising | 55 | 55 |
| Misinformation & Propaganda | 62 | 67 |
| Research Assistance | 10 | 12 |
| Reverse Text | 25 | 30 |
| Scams & Fraud | 62 | 62 |
| Sentiment Analysis | 7 | 8 |
| Substitution Ciphers | 25 | 30 |
| Task Automation | 0 | 0 |

## Latency (defense code only; excludes LLM time)

- Detector raw: 2.2 ms per email; + canonicalise: 3.7 ms per email (3 emails per scenario).
- Gate + canary: 0.001 ms per scenario.
