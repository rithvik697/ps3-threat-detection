"""
APP 2 - EVALUATOR DASHBOARD (Streamlit UI)

Loads App 1's generated logs, runs the evaluation pipeline, and shows the
prioritised SecurityIncidents as colour-coded cards.

Run:  streamlit run app2_evaluator/dashboard.py
"""
import os
import sys
import json
from collections import Counter

# make the evaluator modules importable whether run from repo root or here
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import streamlit as st
from dataclasses import asdict

import config
from incidents import evaluate
from evaluator import load

SEV_COLOR = {"CRITICAL": "#b30000", "HIGH": "#d9480f",
             "MEDIUM": "#b8860b", "LOW": "#2b8a3e"}

st.set_page_config(page_title="Threat Evaluator", page_icon="🛡️", layout="wide")


def incident_card(inc):
    ev = inc.evidence
    sev = ev.get("severity", "")
    color = SEV_COLOR.get(sev, "#666")
    conf = int(round(inc.confidence * 100))
    ips = ", ".join(inc.source_ips)
    extra = ev.get("source_ip_count", len(inc.source_ips)) - len(inc.source_ips)
    if extra > 0:
        ips += f" (+{extra} more)"
    port = f":{inc.target_port}" if inc.target_port else ""
    cve = ""
    if ev.get("top_cve"):
        cve = (f"<div style='margin-top:10px;padding:8px 10px;background:#1b1b1f;"
               f"border-radius:6px;font-size:13px'>🛡️ <b>{ev['top_cve']}</b> "
               f"(CVSS {ev['cvss']}, via {ev.get('cve_source', 'cache')}) — "
               f"{ev['recommended_action']}</div>")
    return f"""
    <div style="border-left:6px solid {color};background:#262730;padding:14px 16px;
                border-radius:8px;margin-bottom:14px">
      <div style="display:flex;justify-content:space-between;align-items:center">
        <div>
          <span style="background:{color};color:#fff;padding:2px 10px;border-radius:6px;
                       font-weight:700;font-size:12px">{sev}</span>
          <b style="margin-left:8px;font-size:16px">{inc.attack_type}</b>
          <span style="color:#888;font-size:12px;margin-left:6px">({ev.get('method')})</span>
        </div>
        <div style="color:#aaa;font-size:13px">confidence&nbsp;{conf}%</div>
      </div>
      <div style="margin-top:8px;color:#cfcfcf;font-size:13px">
        🎯 <b>{inc.target_host}{port}</b> &nbsp;·&nbsp; from {ips}
      </div>
      <div style="margin-top:8px;color:#e6e6e6">{ev.get('reason', '')}</div>
      {cve}
    </div>"""


# --------------------------------------------------------------------- sidebar
st.sidebar.header("⚙️ Evaluate")

# default to App 1's output if present, else the shared data folder
app1_logs = os.path.join(config.PROJECT_ROOT, "app1_generator", "logs.json")
default_logs = app1_logs if os.path.exists(app1_logs) else config.DEFAULT_LOGS

logs_path = st.sidebar.text_input("Logs file (App 1 output)", value=default_logs)
cve_path = st.sidebar.text_input("CVE cache", value=config.DEFAULT_CVE)
use_live = st.sidebar.checkbox("Fetch latest CVEs live from NVD", value=False,
                               help="Pull current CVEs from NVD (falls back to cache).")
run = st.sidebar.button("🔍  Evaluate logs", type="primary", use_container_width=True)

# --------------------------------------------------------------------- header
st.title("🛡️ Log Evaluator")
st.caption("Detects attacks in App 1's logs, correlates CVEs, and prioritises incidents.")

if run:
    if not os.path.exists(logs_path):
        st.error(f"Logs file not found: {logs_path}")
        st.stop()
    try:
        logs = load(logs_path)
        cves = load(cve_path) if os.path.exists(cve_path) else []
    except Exception as e:
        st.error(f"Could not read input: {e}")
        st.stop()
    with st.spinner("Evaluating logs…"):
        incidents = evaluate(logs, cves, use_live=use_live)
    st.session_state["incidents"] = incidents
    st.session_state["n_logs"] = len(logs)

incidents = st.session_state.get("incidents")

if incidents is None:
    st.info("👈 Set the logs file in the sidebar and click **Evaluate logs**.")
    st.stop()

# --------------------------------------------------------------------- summary
sev_counts = Counter(i.evidence.get("severity") for i in incidents)
c1, c2, c3, c4, c5 = st.columns(5)
c1.metric("Events scanned", f'{st.session_state.get("n_logs", 0):,}')
c2.metric("Incidents", len(incidents))
c3.metric("🔴 Critical", sev_counts.get("CRITICAL", 0))
c4.metric("🟠 High", sev_counts.get("HIGH", 0))
c5.metric("🟡 Medium", sev_counts.get("MEDIUM", 0))
st.divider()

if not incidents:
    st.success("No incidents detected — logs look clean.")
    st.stop()

# --------------------------------------------------------------------- cards
for inc in incidents:
    st.markdown(incident_card(inc), unsafe_allow_html=True)

# --------------------------------------------------------------------- raw + download
with st.expander("View raw incident JSON (what the API returns)"):
    st.json([asdict(i) for i in incidents])

st.download_button("⬇️  Download incidents.json",
                   data=json.dumps([asdict(i) for i in incidents], indent=2),
                   file_name="incidents.json", mime="application/json")
