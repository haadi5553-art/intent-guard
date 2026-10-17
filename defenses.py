"""Intent-Guard: detector (+ canonicalisation) + intent gate + canary tokens."""
import base64
import codecs
import re
import time

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import FeatureUnion, make_pipeline

from data import CONTACTS, CANARY

_B64 = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")
_UNLEET = str.maketrans("43105", "aeios")


def normalize(text):
    """Canonicalisation: append decoded views (base64 tokens, ROT13, reversed, un-leeted) so a
    text classifier can see instructions hidden by simple encodings."""
    parts = [text]
    for m in _B64.findall(text):
        try:
            s = base64.b64decode(m + "=" * (-len(m) % 4)).decode("utf-8")
        except Exception:
            continue
        if s and sum(c.isprintable() for c in s) / len(s) > 0.9:
            parts.append(s)
    parts += [codecs.decode(text, "rot13"), text[::-1], text.translate(_UNLEET)]
    return "\n".join(parts)


class Detector:
    """Layer 1: classifies a tool output (email text) as injected (1) or clean (0).
    TF-IDF (char + word n-grams) + logistic regression, CPU only. The interface
    (fit / score_many / flag) matches detector_hf.Detector, so a fine-tuned transformer can be
    swapped in on a machine with Hugging Face access."""

    def __init__(self, thr=0.5, canonicalise=False):
        self.thr, self.canonicalise = thr, canonicalise
        self.model = make_pipeline(
            FeatureUnion([
                ("char", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=3,
                                         sublinear_tf=True, max_features=150_000)),
                ("word", TfidfVectorizer(ngram_range=(1, 2), min_df=2, sublinear_tf=True)),
            ]),
            LogisticRegression(C=10, max_iter=3000, class_weight="balanced"))
        self._cache = {}

    def _prep(self, texts):
        return [normalize(t) for t in texts] if self.canonicalise else list(texts)

    def fit(self, texts, labels):
        self.model.fit(self._prep(texts), labels)
        self._cache = {}
        return self

    def score_many(self, texts):
        return self.model.predict_proba(self._prep(texts))[:, 1]

    def prime(self, texts):
        """Batch-score texts once so later flag() calls are lookups (for fast experiments)."""
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


def gate_allows(call, request, contacts=CONTACTS):
    """Layer 2: a sensitive call is allowed only if the USER's request asked for
    that tool AND the call's target (recipient / file) is named in the request."""
    req = request.lower()
    name, args = call
    if name == "send_email":
        if not any(w in req for w in ("reply", "send", "email")):
            return False
        owners = [p for p, a in contacts.items() if a == args["to"]]
        return bool(owners) and owners[0] in req
    if name == "delete_file":
        return any(w in req for w in ("delete", "remove")) and args["file"].lower() in req
    return True


def canary_hit(call):
    """Layer 3: a planted canary token in an outgoing argument means private
    context is being exfiltrated."""
    return any(CANARY in str(v) for v in call[1].values())


class Defenses:
    def __init__(self, detector=None, gate=False, canary=False):
        self.detector, self.gate, self.canary = detector, gate, canary
        self.spent = 0.0  # seconds spent in gate/canary code
        self.last_reason = ""

    def screen(self, text):
        return bool(self.detector) and self.detector.flag(text)

    def allow(self, call, request):
        t = time.perf_counter()
        ok, self.last_reason = True, ""
        if self.gate and not gate_allows(call, request):
            ok, self.last_reason = False, "intent gate: not what the user asked for"
        elif self.canary and canary_hit(call):
            ok, self.last_reason = False, "canary: private data leaving"
        self.spent += time.perf_counter() - t
        return ok
