"""Streamlit dashboard for the prompt-injection honeypot.

Run with:
    streamlit run honeypot/dashboard.py

It reads from the same SQLite database the server writes to. By default
that's ./data/honeypot.db; override with the HONEYPOT_DB env var.
"""

from __future__ import annotations

import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

# Make `honeypot` importable when run via `streamlit run honeypot/dashboard.py`
_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parent.parent))

from honeypot.classifier import Severity  # noqa: E402
from honeypot.telemetry import Telemetry  # noqa: E402


st.set_page_config(
    page_title="Prompt-Injection Honeypot",
    page_icon="🍯",
    layout="wide",
)


@st.cache_resource
def get_telemetry() -> Telemetry:
    db_path = Path(os.environ.get("HONEYPOT_DB", "./data/honeypot.db"))
    jsonl_path = Path(os.environ.get("HONEYPOT_JSONL", "./data/honeypot.jsonl"))
    return Telemetry(db_path=db_path, jsonl_path=jsonl_path)


def severity_label(s: int | Severity) -> str:
    if isinstance(s, int):
        s = Severity(s)
    return {
        Severity.NONE: "None",
        Severity.LOW: "Low",
        Severity.MEDIUM: "Medium",
        Severity.HIGH: "High",
    }.get(s, str(s))


def main() -> None:
    st.title("🍯 Prompt-Injection Honeypot")
    st.caption("Defensive dashboard — every row is a captured attempt at the honeypot endpoint.")

    telemetry = get_telemetry()

    # ---- sidebar -----------------------------------------------------
    st.sidebar.header("Filters")
    severity_options = ["All", "High", "Medium", "Low", "None"]
    severity_filter = st.sidebar.selectbox("Minimum severity", severity_options, index=1)

    limit = st.sidebar.slider("Max rows to show", min_value=50, max_value=2000, value=200, step=50)
    if st.sidebar.button("Refresh"):
        st.cache_resource.clear()

    severity_at_least = {
        "All": None,
        "High": Severity.HIGH,
        "Medium": Severity.MEDIUM,
        "Low": Severity.LOW,
        "None": Severity.NONE,
    }[severity_filter]

    # ---- top stats ---------------------------------------------------
    total = telemetry.count()
    by_tag = telemetry.count_by_tag()
    attack_count = sum(
        v for k, v in by_tag.items() if k != "benign" and k != "report_finding"
    )

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total events", total)
    col2.metric("Attack attempts", attack_count)
    col3.metric("Distinct attack tags", len([k for k in by_tag if k not in ("benign", "report_finding")]))
    if total:
        col4.metric("Attack ratio", f"{(attack_count / total) * 100:.1f}%")
    else:
        col4.metric("Attack ratio", "—")

    if total == 0:
        st.info("No telemetry yet. Fire some payloads against the honeypot or load the sample logs.")
        st.stop()

    # ---- charts ------------------------------------------------------
    st.subheader("Top attackers")
    top = telemetry.top_attackers(limit=10)
    if top:
        df_top = pd.DataFrame(top)
        fig = px.bar(df_top, x="src_ip", y="count", title="Top 10 source IPs by event count")
        st.plotly_chart(fig, use_container_width=True)

    st.subheader("Attack-tag breakdown")
    df_tags = pd.DataFrame(
        [{"tag": k, "count": v} for k, v in by_tag.items() if k not in ("benign", "report_finding")],
    ).sort_values("count", ascending=False)
    if not df_tags.empty:
        fig = px.bar(df_tags, x="tag", y="count", title="Attack tags detected")
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No attack-tagged events yet.")

    st.subheader("Hourly volume")
    hourly = telemetry.hourly_counts(hours=24)
    if hourly:
        df_hourly = pd.DataFrame(hourly)
        fig = px.line(df_hourly, x="hour", y="count", markers=True, title="Events per hour (last 24h)")
        st.plotly_chart(fig, use_container_width=True)

    # ---- recent events ----------------------------------------------
    st.subheader(f"Recent events (severity ≥ {severity_filter})")
    rows = telemetry.fetch_all(severity_at_least=severity_at_least, limit=limit)
    if not rows:
        st.info("No matching events.")
    else:
        df = pd.DataFrame(rows)
        df["severity"] = df["severity"].apply(severity_label)
        df["tags"] = df["tags"].apply(lambda lst: ", ".join(lst))
        df_display = df[[
            "ts", "src_ip", "user", "tags", "severity", "message",
        ]].rename(columns={
            "ts": "Timestamp",
            "src_ip": "Source IP",
            "user": "User",
            "tags": "Tags",
            "severity": "Severity",
            "message": "Message",
        })
        st.dataframe(df_display, use_container_width=True, hide_index=True)

        # ---- export ----------------------------------------------------
        st.download_button(
            label="Download filtered events as CSV",
            data=df.to_csv(index=False).encode("utf-8"),
            file_name=f"honeypot_events_{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}.csv",
            mime="text/csv",
        )


if __name__ == "__main__":
    main()