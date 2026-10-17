"""Baseline vs defenses over 5 seeds (simulated agent). Writes results.md, results.json,
asr.png, detector_recall.png.   Usage: python eval.py
"""
import json
import time
from collections import defaultdict

import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

import agent
from data import ADAPT_TAGS, make_bipia_docs, make_set
from defenses import Defenses, Detector

SEEDS = [0, 1, 2, 3, 4]
N_ATTACK, N_BENIGN, N_TRAIN, N_BIPIA_TRAIN, N_BIPIA_TEST = 200, 200, 600, 300, 200
GOALS = ["exfil", "delete", "leak_reply"]
CONFIGS = {  # name -> (detector variant or None, gate, canary)
    "no defense": (None, False, False),
    "detector (raw)": ("raw", False, False),
    "detector + canonicalise": ("norm", False, False),
    "gate only": (None, True, False),
    "canary only": (None, False, True),
    "gate + canary": (None, True, True),
    "all three": ("norm", True, True),
}


def prf(tp, fp, fn, tn):
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * p * r / (p + r) if p + r else 0.0
    return p, r, f1, fp / (fp + tn) if fp + tn else 0.0


def doc_eval(det, pos_emails, neg_texts):
    """Returns (P, R, F1, FPR, recall-by-tag)."""
    flags = [det.flag(e.text) for e in pos_emails]
    fp = sum(det.flag(t) for t in neg_texts)
    tp = sum(flags)
    by = defaultdict(list)
    for e, f in zip(pos_emails, flags):
        by[e.tag].append(f)
    return prf(tp, fp, len(flags) - tp, len(neg_texts) - fp) + ({k: float(np.mean(v)) for k, v in by.items()},)


def make_def(cfg, dets):
    d, gate, canary = cfg
    return Defenses(dets.get(d), gate, canary)


def asr(scns, cfg, dets):
    dfn = make_def(cfg, dets)
    hits = {g: [] for g in GOALS}
    for s in scns:
        ex, _ = agent.run(s, dfn)
        hits[s.goal["kind"]].append(agent.attack_success(s, ex))
    out = {"all": 100 * np.mean([x for v in hits.values() for x in v])}
    out.update({g: 100 * np.mean(v) for g, v in hits.items() if v})
    return out


def benign_utility(scns, cfg, dets):
    dfn = make_def(cfg, dets)
    ok = []
    for s in scns:
        ex, q = agent.run(s, dfn)
        ok.append(agent.task_success(s, ex, q))
    return 100 * np.mean(ok), 1000 * dfn.spent / len(scns)


def latency_ms(det, texts, n=60):
    t = time.perf_counter()
    for x in texts[:n]:
        det.flag_uncached(x)
    return 1000 * (time.perf_counter() - t) / n


def main():
    runs = []
    for seed in SEEDS:
        train = make_set(10_000 + seed, "train", N_TRAIN) + make_set(20_000 + seed, "benign", N_TRAIN)
        tx = [e.text for s in train for e in s.emails]
        ty = [int(e.injected) for s in train for e in s.emails]
        bt = make_bipia_docs(30_000 + seed, "train", N_BIPIA_TRAIN)
        tx += [e.text for e in bt]; ty += [1] * len(bt)
        dets = {"raw": Detector().fit(tx, ty), "norm": Detector(canonicalise=True).fit(tx, ty)}

        test = make_set(seed, "test", N_ATTACK)
        adapt = make_set(1000 + seed, "adapt", N_ATTACK)
        ben = make_set(2000 + seed, "benign", N_BENIGN)
        bipia = make_bipia_docs(3000 + seed, "test", N_BIPIA_TEST)
        neg = [e.text for s in ben for e in s.emails]
        all_texts = neg + [e.text for s in test + adapt for e in s.emails] + [e.text for e in bipia]
        for d in dets.values():
            d.prime(all_texts)

        r = {"det": {}, "cfg": {}, "latency_ms_doc": {}}
        for dn, d in dets.items():
            r["det"][dn] = {
                "tool_test": doc_eval(d, [e for s in test for e in s.emails if e.injected], neg),
                "tool_adapt": doc_eval(d, [e for s in adapt for e in s.emails if e.injected], neg),
                "bipia_test": doc_eval(d, bipia, neg)}
            r["latency_ms_doc"][dn] = latency_ms(d, neg)
        for name, cfg in CONFIGS.items():
            u, ms = benign_utility(ben, cfg, dets)
            r["cfg"][name] = {"test": asr(test, cfg, dets), "adapt": asr(adapt, cfg, dets),
                              "utility": u, "gate_canary_ms": ms}
        runs.append(r)
        print(f"seed {seed} done", flush=True)

    ms = lambda v: f"{np.mean(v):.1f} ± {np.std(v):.1f}"
    L = ["## Attack success rate (%), simulated agent - lower is better (mean ± sd, 5 seeds, 200 attacks per set)\n",
         "| Defense | Test wording | Adaptive | Adaptive: exfil | Adaptive: delete | Adaptive: leak-in-reply | Benign task success (%) |",
         "| --- | --- | --- | --- | --- | --- | --- |"]
    summ = {}
    for n in CONFIGS:
        g = lambda sp, k: [r["cfg"][n][sp].get(k, np.nan) for r in runs]
        L.append(f"| {n} | {ms(g('test','all'))} | {ms(g('adapt','all'))} | {ms(g('adapt','exfil'))} | "
                 f"{ms(g('adapt','delete'))} | {ms(g('adapt','leak_reply'))} | "
                 f"{ms([r['cfg'][n]['utility'] for r in runs])} |")
        summ[n] = {"test": np.mean(g("test", "all")), "adapt": np.mean(g("adapt", "all"))}

    L += ["\n## Detector, document level (mean ± sd over 5 seeds; negatives = benign emails incl. hard benign)\n",
          "| Detector | Attack set | Precision % | Recall % | F1 % | False positive rate % |", "| --- | --- | --- | --- | --- | --- |"]
    labels = {"tool_test": "Tool-abuse, held-out wording", "tool_adapt": "Tool-abuse, adaptive",
              "bipia_test": "BIPIA public hold-out (test attacks on test emails)"}
    for dn, dl in (("raw", "raw"), ("norm", "+ canonicalise")):
        for key, lab in labels.items():
            cols = [ms([100 * r["det"][dn][key][i] for r in runs]) for i in range(4)]
            L.append(f"| {dl} | {lab} | " + " | ".join(cols) + " |")

    L += ["\n## Detector recall (%) by adaptive style (tool-abuse adaptive set)\n",
          "| Style | raw | + canonicalise |", "| --- | --- | --- |"]
    rec = {dn: {t: np.mean([100 * r["det"][dn]["tool_adapt"][4].get(t, np.nan) for r in runs]) for t in ADAPT_TAGS}
           for dn in ("raw", "norm")}
    for t in ADAPT_TAGS:
        L.append(f"| {t} | {rec['raw'][t]:.0f} | {rec['norm'][t]:.0f} |")

    cats = sorted({c for r in runs for c in r["det"]["raw"]["bipia_test"][4]})
    L += ["\n## Detector recall (%) by BIPIA test attack category (raw vs + canonicalise)\n",
          "| Category | raw | + canonicalise |", "| --- | --- | --- |"]
    for c in cats:
        a = np.nanmean([100 * r["det"]["raw"]["bipia_test"][4].get(c, np.nan) for r in runs])
        b = np.nanmean([100 * r["det"]["norm"]["bipia_test"][4].get(c, np.nan) for r in runs])
        L.append(f"| {c} | {a:.0f} | {b:.0f} |")

    L += ["\n## Latency (defense code only; excludes LLM time)\n",
          f"- Detector raw: {np.mean([r['latency_ms_doc']['raw'] for r in runs]):.1f} ms per email; "
          f"+ canonicalise: {np.mean([r['latency_ms_doc']['norm'] for r in runs]):.1f} ms per email (3 emails per scenario).",
          f"- Gate + canary: {np.mean([r['cfg']['all three']['gate_canary_ms'] for r in runs]):.3f} ms per scenario."]
    open("results.md", "w").write("\n".join(L) + "\n")
    json.dump(runs, open("results.json", "w"), indent=1, default=float)
    print("\n".join(L))

    fig, ax = plt.subplots(figsize=(10, 4.8))
    x = np.arange(len(CONFIGS)); w = 0.38
    for off, key, lab in ((-w / 2, "test", "Held-out test wording"), (w / 2, "adapt", "Adaptive (encodings, paraphrase)")):
        b = ax.bar(x + off, [summ[n][key] for n in CONFIGS], w, label=lab)
        ax.bar_label(b, fmt="%.0f", fontsize=8)
    ax.set_xticks(x, list(CONFIGS), rotation=20, ha="right")
    ax.set_ylabel("Attack success rate (%)")
    ax.set_title("Attack success rate by defense (simulated agent, mean of 5 seeds)")
    ax.legend(); fig.tight_layout(); fig.savefig("asr.png", dpi=150)

    fig, ax = plt.subplots(figsize=(9, 4.2))
    x = np.arange(len(ADAPT_TAGS))
    for off, dn, lab in ((-w / 2, "raw", "raw"), (w / 2, "norm", "+ canonicalise")):
        b = ax.bar(x + off, [rec[dn][t] for t in ADAPT_TAGS], w, label=lab)
        ax.bar_label(b, fmt="%.0f", fontsize=8)
    ax.set_xticks(x, ADAPT_TAGS); ax.set_ylim(0, 110)
    ax.set_ylabel("Detector recall (%)"); ax.set_title("Detector recall by adaptive attack style (mean of 5 seeds)")
    ax.legend(); fig.tight_layout(); fig.savefig("detector_recall.png", dpi=150)


if __name__ == "__main__":
    main()
