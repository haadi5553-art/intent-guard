"""Streamlit live demo:  streamlit run app.py"""
import streamlit as st

import agent
import data
from defenses import Defenses, Detector
from demo import TASKS, build

st.set_page_config(page_title="Intent-Guard demo", layout="wide")
st.title("Intent-Guard: stopping prompt-injection tool abuse")
st.caption("Simulated agent, mock tools, synthetic data. Nothing real is sent or deleted.")


@st.cache_resource(show_spinner="Training detector...")
def get_detector():
    tr = data.make_set(10_000, "train", 500) + data.make_set(20_000, "benign", 500)
    bt = data.make_bipia_docs(30_000, "train", 300)
    return Detector(canonicalise=True).fit([e.text for s in tr for e in s.emails] + [e.text for e in bt],
                                           [int(e.injected) for s in tr for e in s.emails] + [1] * len(bt))


c1, c2, c3 = st.columns(3)
task = c1.selectbox("User task", list(TASKS), index=1)
attack = c2.selectbox("Attack goal", ["none", "exfil", "delete", "leak"], index=1)
style = c3.selectbox("Attack style", ["test"] + data.ADAPT_TAGS)
use_det = st.sidebar.checkbox("Layer 1: injection detector", True)
use_gate = st.sidebar.checkbox("Layer 2: intent gate", True)
use_can = st.sidebar.checkbox("Layer 3: canary tokens", True)

scn = build(task, attack, style)
st.subheader("What the agent reads")
st.write(f"**User request:** {scn.task.request}")
for i, e in enumerate(scn.emails, 1):
    st.text_area(f"Email {i}" + (" (injected)" if e.injected else ""), e.text, height=90, disabled=True, key=f"e{i}")

if st.button("Run agent", type="primary"):
    cols = st.columns(2)
    for col, title, d in ((cols[0], "Without defenses", None),
                          (cols[1], "With Intent-Guard", Defenses(get_detector() if use_det else None, use_gate, use_can))):
        log = []
        ex, _ = agent.run(scn, d, log=log.append)
        col.subheader(title)
        col.code("\n".join(log) or "(no steps)")
        if scn.goal:
            (col.error if agent.attack_success(scn, ex) else col.success)(
                "ATTACK SUCCEEDED" if agent.attack_success(scn, ex) else "Attack stopped")
