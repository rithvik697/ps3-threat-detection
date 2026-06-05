import streamlit as st
import pandas as pd
import json
import subprocess
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
GENERATOR = SCRIPT_DIR / "generator.py"
LOGS_JSON = SCRIPT_DIR / "logs.json"
LOGS_CSV = SCRIPT_DIR / "logs.csv"
LOGS_SYSLOG = SCRIPT_DIR / "logs.syslog"

# -----------------------------
# PAGE CONFIG
# -----------------------------

st.set_page_config(
    page_title="Cyber Log Generator",
    page_icon="🛡️",
    layout="wide"
)

# -----------------------------
# TITLE
# -----------------------------

st.title("🛡️Log Generator")
st.markdown(
    "Generate realistic multi-source cyber logs for testing and analysis.")

# -----------------------------
# GENERATE BUTTON
# -----------------------------

log_count = st.number_input(
    "Number of logs",
    min_value=100,
    max_value=200000,
    value=50000,
    step=1000,
)

if st.button(f"🔄 Generate {log_count:,} Logs"):

    result = subprocess.run(
        [sys.executable, str(GENERATOR), "--lines", str(int(log_count)), "--out", str(LOGS_JSON)],
        cwd=SCRIPT_DIR,
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        st.error("Log generation failed.")
        st.code(result.stderr or result.stdout)
        st.stop()

    st.success(f"{int(log_count):,} Logs Generated Successfully!")

    st.rerun()

# -----------------------------
# LOAD LOGS
# -----------------------------

if LOGS_JSON.exists():

    with open(LOGS_JSON, "r") as file:
        logs = json.load(file)

    df_logs = pd.DataFrame(logs)

else:

    st.warning("No logs generated yet.")
    st.stop()

# -----------------------------
# METRICS
# -----------------------------

st.divider()

col1, col2, col3 = st.columns(3)

col1.metric("📄 Total Logs", len(df_logs))

col2.metric(
    "🖥️ Hosts",
    df_logs["host"].nunique()
)

col3.metric(
    "📡 Log Sources",
    df_logs["source_type"].nunique()
)

# -----------------------------
# SOURCE TYPE COUNTS
# -----------------------------

auth_logs = len(
    df_logs[df_logs["source_type"] == "AUTH"]
)

web_logs = len(
    df_logs[df_logs["source_type"] == "WEB"]
)

app_logs = len(
    df_logs[df_logs["source_type"] == "APPLICATION"]
)

firewall_logs = len(
    df_logs[df_logs["source_type"] == "FIREWALL"]
)

network_logs = len(
    df_logs[df_logs["source_type"] == "NETWORK"]
)

st.divider()

st.subheader("📊 Log Source Summary")

c1, c2, c3, c4, c5 = st.columns(5)

c1.metric("AUTH", auth_logs)
c2.metric("WEB", web_logs)
c3.metric("APPLICATION", app_logs)
c4.metric("FIREWALL", firewall_logs)
c5.metric("NETWORK", network_logs)

# -----------------------------
# SOURCE DISTRIBUTION
# -----------------------------

st.divider()

st.subheader("📈 Log Source Distribution")

source_counts = df_logs["source_type"].value_counts()

st.bar_chart(source_counts)

# -----------------------------
# LOG PREVIEW
# -----------------------------

st.divider()

st.subheader("📜 Generated Logs Preview")

st.dataframe(
    df_logs.head(100),
    use_container_width=True
)

st.info(
    f"Showing first 100 records out of {len(df_logs):,} generated logs."
)

# -----------------------------
# EXPORT LOGS
# -----------------------------

st.divider()

st.subheader("📥 Export Logs")

col1, col2, col3 = st.columns(3)

# JSON Download
with open(LOGS_JSON, "rb") as f:

    col1.download_button(
        "📄 Download JSON",
        f,
        file_name="logs.json",
        mime="application/json"
    )

# CSV Download
if LOGS_CSV.exists():

    with open(LOGS_CSV, "rb") as f:

        col2.download_button(
            "📊 Download CSV",
            f,
            file_name="logs.csv",
            mime="text/csv"
        )

# SYSLOG Download
if LOGS_SYSLOG.exists():

    with open(LOGS_SYSLOG, "rb") as f:

        col3.download_button(
            "📡 Download Syslog",
            f,
            file_name="logs.syslog",
            mime="text/plain"
        )

# -----------------------------
# SAMPLE LOG FORMAT
# -----------------------------

st.divider()

st.subheader("📝 Log Structure")

sample = df_logs.iloc[0].to_dict()

st.json(sample)

# -----------------------------
# FOOTER
# -----------------------------

st.divider()

st.caption(
    "Hackathon Project | App 1 - Multi Source Cyber Log Generator"
)
