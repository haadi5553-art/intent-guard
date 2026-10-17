"""OPTIONAL: transformer detector (same interface as defenses.Detector).

NOT RUN in the sandbox where this project was written (Hugging Face was unreachable there),
so treat it as untested starter code. On your machine:
    pip install -r requirements-hf.txt
Use it in eval.py / eval_llm.py by replacing Detector() with HFDetector().
"""
import numpy as np
import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer

from defenses import normalize


class HFDetector:
    def __init__(self, name="microsoft/deberta-v3-small", thr=0.5, canonicalise=True,
                 epochs=2, lr=2e-5, bs=16, max_len=256):
        self.thr, self.canonicalise, self.epochs, self.lr, self.bs, self.max_len = thr, canonicalise, epochs, lr, bs, max_len
        self.tok = AutoTokenizer.from_pretrained(name)
        self.model = AutoModelForSequenceClassification.from_pretrained(name, num_labels=2)
        self.dev = "cuda" if torch.cuda.is_available() else "cpu"
        self.model.to(self.dev)
        self._cache = {}

    def _prep(self, texts):
        return [normalize(t) for t in texts] if self.canonicalise else list(texts)

    def _enc(self, texts):
        return self.tok(texts, truncation=True, max_length=self.max_len, padding=True, return_tensors="pt").to(self.dev)

    def fit(self, texts, labels):
        texts, labels = self._prep(texts), np.array(labels)
        opt = torch.optim.AdamW(self.model.parameters(), lr=self.lr)
        self.model.train()
        for _ in range(self.epochs):
            for _ in range(max(1, len(texts) // self.bs)):
                idx = np.random.choice(len(texts), self.bs)
                batch = self._enc([texts[j] for j in idx])
                out = self.model(**batch, labels=torch.tensor(labels[idx]).to(self.dev))
                out.loss.backward(); opt.step(); opt.zero_grad()
        self.model.eval(); self._cache = {}
        return self

    @torch.no_grad()
    def score_many(self, texts):
        texts, out = self._prep(texts), []
        for i in range(0, len(texts), 32):
            out.append(torch.softmax(self.model(**self._enc(texts[i:i + 32])).logits, -1)[:, 1].cpu().numpy())
        return np.concatenate(out)

    def prime(self, texts):
        todo = [t for t in dict.fromkeys(texts) if t not in self._cache]
        if todo:
            for t, s in zip(todo, self.score_many(todo)):
                self._cache[t] = s >= self.thr

    def flag(self, text):
        if text not in self._cache:
            self._cache[text] = bool(self.score_many([text])[0] >= self.thr)
        return self._cache[text]

    def flag_uncached(self, text):
        return bool(self.score_many([text])[0] >= self.thr)
