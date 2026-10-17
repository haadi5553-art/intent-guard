# Intent-Guard: defending LLM agents against indirect prompt injection (tool abuse)

AI Security, Assignment 3 (BS Cyber Security, Semester 4). Individual project.
Runs locally on mock tools; no real emails, files, accounts, users or live services are involved.

## Quick start
```
pip install -r requirements.txt
python eval.py            # ~1 min on CPU: results.md, results.json, asr.png, detector_recall.png
python -m pytest -q tests # 8 unit tests
python demo.py            # step-by-step terminal demo (see --help)
streamlit run app.py      # browser demo with toggles for each defense layer
```
Real-LLM experiment (needs Ollama on your machine): `ollama pull llama3.1:8b`, then
`python eval_llm.py --model llama3.1:8b --n 60` (writes `results_llm.md`).

## Problem and threat model
An LLM agent that reads untrusted content (emails) and calls tools can be hijacked by instructions
hidden in that content (indirect prompt injection -> tool abuse). The attacker can only place text
in an email the agent reads. Three attacker goals:
- `exfil`: make the agent email the user's private notes to an attacker address
- `delete`: make the agent delete a protected file
- `leak_reply`: make the agent's *legitimate* reply to the user's contact also carry private notes

Attack success = the attacker's tool call actually executed.

## Defense: three layers (`defenses.py`)
1. **Detector (+ canonicalisation):** TF-IDF + logistic regression flags injected emails; flagged emails are
   quarantined before the agent sees them. Canonicalisation appends decoded views (base64, ROT13, reversed,
   un-leeted) so simple encodings stop hiding the instruction.
2. **Intent gate:** `send_email` / `delete_file` runs only if the *user's own request* asked for that tool and
   names the recipient / file. Independent of how the injection is worded.
3. **Canary token:** a fake secret planted in the private notes; any outgoing argument containing it is blocked.

## Data
- **Public:** BIPIA (Microsoft, MIT licence; `data/bipia/`): 100 email bodies and 150 text-attack instructions
  (train and test categories are disjoint; test includes base64, ciphers, reverse text, emoji).
- **Synthetic:** user tasks, tool-abuse injections in 3 disjoint wording sets (TRAIN / TEST / ADAPT), benign
  emails, and "hard benign" emails that look like attacks ("URGENT", "ignore the earlier agenda").
- Detector training and testing use disjoint wording and disjoint BIPIA host emails and attack categories.

## Results (simulated agent, 5 seeds, 200 attacks per set; full tables in `results.md`)
| Defense | ASR %, test wording | ASR %, adaptive | Benign task success % |
| --- | --- | --- | --- |
| no defense | 89.4 | 90.5 | 100 |
| detector (raw) | 10.5 | 49.2 | 100 |
| detector + canonicalise | 9.3 | 23.6 | 100 |
| gate only | 7.3 | 7.4 | 100 |
| canary only | 54.6 | 50.8 | 100 |
| gate + canary | 1.4 | 2.5 | 100 |
| **all three** | **0.1** | **0.5** | 100 |

What to take from it:
- No single layer is enough. The gate cannot stop `leak_reply` (91% ASR with gate only); the canary misses
  attacks that carry no secret (delete: 91%); the detector misses encoded or task-like injections.
- Canonicalisation lifts adaptive detector recall from 46% to 75% (ROT13 4% -> 88%, reverse 38% -> 97%, base64 0% -> 56%).
- On the BIPIA public hold-out the detector recall is only ~32-34%: BIPIA attacks are polite task requests
  ("Write a script to rename files...") that do not look like injections. This is the case for gate-style defenses.
- Latency (defense code only): detector 2.2 ms per email (3.7 ms with canonicalisation); gate + canary ~0.001 ms per scenario.

## Honest limitations (also in the report)
- **The agent in `eval.py` is simulated**: it obeys an injection it sees with probability 0.9 and leaks the full
  notes (incl. canary) 75% of the time. These ASR numbers show how the *defense layers* behave, not how any real
  LLM behaves. `llm_agent.py` + `eval_llm.py` run the same experiment with a real model; **they were tested only
  against a mock server here (the sandbox could not download model weights), so the real-LLM numbers have to be
  produced on your machine** and added to the report.
- The tool-abuse hold-out wording shares attack families with training, so detector scores there are optimistic.
- Benign false-positive rate was 0% on ~600 benign emails per seed; that is a small, partly synthetic set.
- The gate knows only two tools and matches names by string; a legitimate but unusual request could be blocked.
- Detector is TF-IDF + LR, not the DeBERTa named in the proposal. `detector_hf.py` is an untested starter for it.
- Adaptive attacks are 8 hand-written styles, not an optimizing attacker. The leet style also garbles the target
  file name, which would hurt a real attacker.

## Files
| File | Role |
| --- | --- |
| `data.py` | scenario generator, BIPIA loaders, TRAIN/TEST/ADAPT injection sets |
| `agent.py` | simulated vulnerable agent + mock tools, success metrics |
| `defenses.py` | detector, canonicalisation, intent gate, canary |
| `eval.py` | main experiment, tables and charts |
| `llm_agent.py`, `eval_llm.py` | real-LLM (Ollama) adapter and experiment; `--fake` mock for plumbing check |
| `detector_hf.py` | optional transformer detector (untested) |
| `demo.py`, `app.py` | terminal and Streamlit demos |
| `tests/` | unit tests |
| `VIVA.md` | viva preparation notes |

BIPIA: Yi et al., "Benchmarking and Defending Against Indirect Prompt Injection Attacks on LLMs", MIT licence (`data/bipia/LICENSE`).
