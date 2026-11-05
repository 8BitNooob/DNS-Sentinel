"""Streamlit dashboard for DNS Sentinel."""

from pathlib import Path

import pandas as pd
import streamlit as st
import yaml

from dashboard import (
    collector_running,
    load_events,
    load_health,
    load_table,
    start_collector,
    stop_collector,
    format_event_timestamps,
    workstation_queries,
)

ROOT = Path(__file__).parent
CONFIG_PATH = ROOT / "config" / "settings.yaml"


@st.cache_data(ttl=5)
def settings() -> dict:
    with CONFIG_PATH.open(encoding="utf-8") as file:
        return yaml.safe_load(file)


def database_path() -> Path:
    return ROOT / settings()["database_path"]


def health_path() -> Path:
    return ROOT / settings().get("health_path", "outputs/collector_health.json")


def stop_path() -> Path:
    return ROOT / settings().get("stop_path", "outputs/collector.stop")


def collector_controls() -> None:
    health = load_health(health_path())
    running = collector_running(health)
    st.sidebar.subheader("Collector")
    st.sidebar.write(f"Status: **{health.get('status', 'unknown')}**")
    if health.get("error"):
        st.sidebar.error(str(health["error"]))
    if running:
        if st.sidebar.button("Stop collector"):
            stop_collector(st.session_state.get("collector_process"), stop_path())
            st.rerun()
    elif st.sidebar.button("Start collector"):
        st.session_state["collector_process"] = start_collector(CONFIG_PATH)
        st.rerun()
    if st.sidebar.button("Refresh now"):
        st.cache_data.clear()
        st.rerun()


def overview(events: pd.DataFrame) -> None:
    st.header("Overview")
    events = workstation_queries(events)
    display_events = format_event_timestamps(events)
    health = load_health(health_path())
    columns = st.columns(4)
    columns[0].metric("Events", len(events))
    columns[1].metric("Clients", events["source_ip"].nunique() if not events.empty else 0)
    columns[2].metric("Domains", events["qname"].nunique() if not events.empty else 0)
    columns[3].metric("Collector", str(health.get("status", "unknown")))
    if events.empty:
        st.info("No DNS events have been collected yet.")
        return
    chart = events.copy()
    chart["observed_at"] = pd.to_datetime(chart["observed_at"])
    per_minute = chart.set_index("observed_at").resample("1min").size().rename("queries")
    st.subheader("DNS activity")
    st.line_chart(per_minute)
    st.dataframe(display_events.head(25), use_container_width=True, hide_index=True)


def live_traffic(events: pd.DataFrame) -> None:
    st.header("Live Traffic")
    show_responses = st.checkbox(
        "Include DNS responses",
        value=False,
        help="Disabled shows only queries originating from this workstation. Enable it to inspect resolver responses.",
    )
    displayed = events if show_responses else workstation_queries(events)
    displayed = format_event_timestamps(displayed)
    st.caption(
        "By default, this view shows workstation-originated DNS queries. "
        "Pending means no matching response was observed; it is not an NXDOMAIN result. "
        "NXDOMAIN requires response_code=3 in an observed response."
    )
    st.dataframe(displayed, use_container_width=True, hide_index=True)
    st.download_button("Export traffic CSV", displayed.to_csv(index=False), "dns-traffic.csv", "text/csv")


def alerts_incidents(path: Path) -> None:
    st.header("Alerts / Incidents")
    alerts = load_table(path, "alerts")
    incidents = load_table(path, "incidents")
    st.subheader("Alerts")
    st.dataframe(alerts, use_container_width=True, hide_index=True)
    st.subheader("Incidents")
    st.dataframe(incidents, use_container_width=True, hide_index=True)


def client_profiles(path: Path) -> None:
    st.header("Client Profiles")
    st.dataframe(load_table(path, "client_baselines"), use_container_width=True, hide_index=True)


def domain_investigation(events: pd.DataFrame) -> None:
    st.header("Domain Investigation")
    domain = st.text_input("Domain contains", "")
    filtered = events[events["qname"].str.contains(domain, case=False, na=False)] if domain else events
    st.dataframe(format_event_timestamps(filtered), use_container_width=True, hide_index=True)


def offline_analysis() -> None:
    st.header("Offline Analysis")
    st.info("Offline adapters are available for CSV, PCAP, and Zeek logs.")
    uploaded = st.file_uploader("Upload an event CSV for preview", type=["csv"])
    if uploaded is not None:
        st.dataframe(pd.read_csv(uploaded), use_container_width=True, hide_index=True)


def settings_page() -> None:
    st.header("Settings")
    st.json(settings())
    st.caption("Windows-only capture uses Npcap and Scapy. Dashboard refresh does not restart collection.")


def render_page(page: str, events: pd.DataFrame) -> None:
    if page == "Overview":
        overview(events)
    elif page == "Live Traffic":
        live_traffic(events)
    elif page == "Alerts / Incidents":
        alerts_incidents(database_path())
    elif page == "Client Profiles":
        client_profiles(database_path())
    elif page == "Domain Investigation":
        domain_investigation(events)
    elif page == "Offline Analysis":
        offline_analysis()
    else:
        settings_page()


@st.fragment(run_every=5)
def auto_refreshing_page(page: str) -> None:
    render_page(page, load_events(database_path()))


def main() -> None:
    st.set_page_config(page_title="DNS Sentinel", page_icon=":shield:", layout="wide")
    st.title("DNS Sentinel")
    collector_controls()
    page = st.sidebar.radio(
        "Page",
        ["Overview", "Live Traffic", "Alerts / Incidents", "Client Profiles",
         "Domain Investigation", "Offline Analysis", "Settings"],
    )
    auto_refreshing_page(page)


if __name__ == "__main__":
    main()
