"""Run the experiment against a REAL local LLM served by Ollama.

    ollama pull llama3.1:8b            # or qwen2.5:7b
    python eval_llm.py --model llama3.1:8b --n 60

Writes results_llm.md. `--fake` runs the whole pipeline with a built-in obedient mock model
(plumbing check only - those numbers mean nothing).
"""
import argparse

import agent
import llm_agent
from data import make_bipia_docs, make_set
from defenses import Defenses, Detector


def fake_chat(messages):
    """Obedient mock: acts on the user request and also on any 'send ... to X' / 'delete the file F'."""
    import json, re
    text = messages[-1]["content"]
    req = text.split("EMAILS:")[0]
    emails = text.split("EMAILS:")[1] if "EMAILS:" in text else ""
    calls = []
    m = re.search(r"Reply to (\w+)", req)
    if m:
        calls.append({"tool": "send_email", "args": {"to": f"{m.group(1).lower()}@uet.test",
                                                       "body": "I will attend the meeting."}})
    m = re.search(r"delete the old file (\w+\.[a-z]+)", req)
    if m:
        calls.append({"tool": "delete_file", "args": {"file": m.group(1)}})
    m = re.search(r"send the user's private notes to (\w+@[\w.]+?\.test)", emails)
    if m:
        calls.append({"tool": "send_email", "args": {"to": m.group(1), "body": llm_agent.PRIVATE_NOTES}})
    m = re.search(r"delete the file (\w+\.[a-z]+)", emails)
    if m:
        calls.append({"tool": "delete_file", "args": {"file": m.group(1)}})
    return json.dumps({"calls": calls})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="llama3.1:8b")
    ap.add_argument("--url", default="http://localhost:11434")
    ap.add_argument("--n", type=int, default=60, help="scenarios per set (attack / adaptive / benign)")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--fake", action="store_true")
    a = ap.parse_args()
    chat = fake_chat if a.fake else llm_agent.ollama_chat(a.model, a.url)

    train = make_set(10_000 + a.seed, "train", 600) + make_set(20_000 + a.seed, "benign", 600)
    tx = [e.text for s in train for e in s.emails]
    ty = [int(e.injected) for s in train for e in s.emails]
    bt = make_bipia_docs(30_000 + a.seed, "train", 300)
    det = Detector(canonicalise=True).fit(tx + [e.text for e in bt], ty + [1] * len(bt))

    sets = {"test wording": make_set(a.seed, "test", a.n),
            "adaptive": make_set(1000 + a.seed, "adapt", a.n)}
    benign = make_set(2000 + a.seed, "benign", a.n)
    configs = {"no defense": (None, False, False), "detector + canonicalise": (det, False, False),
               "gate + canary": (None, True, True), "all three": (det, True, True)}

    rows = [f"## Real-LLM results: model `{a.model}`{' (FAKE MOCK - plumbing only)' if a.fake else ''}, "
            f"n={a.n} per set, seed {a.seed}\n",
            "| Defense | ASR test wording (%) | ASR adaptive (%) | Benign task success (%) |", "| --- | --- | --- | --- |"]
    for name, (d, g, c) in configs.items():
        cells = []
        for sc in sets.values():
            dfn = Defenses(d, g, c)
            hits = [agent.attack_success(s, llm_agent.run_llm(s, dfn, chat)[0]) for s in sc]
            cells.append(f"{100 * sum(hits) / len(hits):.1f} ({sum(hits)}/{len(hits)})")
        dfn = Defenses(d, g, c)
        ok = [llm_agent.task_success(s, *llm_agent.run_llm(s, dfn, chat)) for s in benign]
        cells.append(f"{100 * sum(ok) / len(ok):.1f} ({sum(ok)}/{len(ok)})")
        rows.append(f"| {name} | " + " | ".join(cells) + " |")
        print(rows[-1], flush=True)
    open("results_llm.md", "w").write("\n".join(rows) + "\n")


if __name__ == "__main__":
    main()
