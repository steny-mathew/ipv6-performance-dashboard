"""IPv4/IPv6 connectivity and performance dashboard."""
from __future__ import annotations
import ipaddress
import socket
import ssl
import time
from datetime import datetime, timezone
from pathlib import Path
from http.client import HTTPResponse

import certifi
import pandas as pd
import plotly.express as px
import streamlit as st

APP_DIR = Path(__file__).resolve().parent
DATA_FILE = APP_DIR / "data" / "measurements.csv"
# https_ms is retained so older CSV history is not discarded when the file is upgraded.
FIELDS = ["timestamp_utc", "host", "protocol", "repetition", "dns_ms", "tcp_connect_ms",
          "tls_handshake_ms", "request_headers_ms", "https_ms", "http_status", "resolved_ip", "success", "error"]
DEFAULT_HOSTS = ["www.cloudflare.com", "www.google.com", "www.wikipedia.org"]


def valid_host(value: str) -> str:
    host = value.strip().lower().rstrip(".")
    if not host or len(host) > 253 or any(c.isspace() for c in host) or "/" in host or ":" in host:
        raise ValueError(f"Invalid hostname: {value!r}. Enter a hostname only, without https:// or a path.")
    return host


def resolve(host: str, family: int):
    started = time.perf_counter()
    infos = socket.getaddrinfo(host, 443, family, socket.SOCK_STREAM)
    elapsed = (time.perf_counter() - started) * 1000
    unique = []
    for info in infos:
        address = info[4][0]
        if address not in unique:
            unique.append(address)
    if not unique:
        raise OSError("DNS returned no usable addresses")
    return elapsed, unique


def request_https(host: str, family: int, addresses: list[str], timeout: float, row: dict):
    """Measure TCP setup, TLS handshake, then request-to-response-header time."""
    last_error = None
    for address in addresses:
        sock = None
        tls = None
        row["resolved_ip"] = address
        row["tcp_connect_ms"] = None
        row["tls_handshake_ms"] = None
        row["request_headers_ms"] = None
        try:
            sock = socket.socket(family, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            started = time.perf_counter()
            sock.connect((address, 443))
            row["tcp_connect_ms"] = round((time.perf_counter() - started) * 1000, 3)

            context = ssl.create_default_context(cafile=certifi.where())
            started = time.perf_counter()
            tls = context.wrap_socket(sock, server_hostname=host)
            sock = None  # ownership moved to TLS socket
            row["tls_handshake_ms"] = round((time.perf_counter() - started) * 1000, 3)

            started = time.perf_counter()
            tls.sendall((f"HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: IPv6-Performance-Analysis-Student-Project/1.0\r\nConnection: close\r\n\r\n").encode("ascii"))
            response = HTTPResponse(tls)
            response.begin()
            row["request_headers_ms"] = round((time.perf_counter() - started) * 1000, 3)
            status = response.status
            response.close()
            return status, address
        except Exception as exc:
            last_error = exc
        finally:
            if sock is not None:
                sock.close()
            if tls is not None:
                tls.close()
    raise last_error or OSError("HTTPS connection failed")


def run_one(host: str, label: str, family: int, timeout: float) -> dict:
    row = {"timestamp_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"), "host": host,
           "protocol": label, "dns_ms": None, "tcp_connect_ms": None, "tls_handshake_ms": None,
           "request_headers_ms": None, "https_ms": None, "http_status": None, "resolved_ip": None,
           "success": False, "error": ""}
    try:
        dns_ms, addresses = resolve(host, family)
        row["dns_ms"] = round(dns_ms, 3)
        status, address = request_https(host, family, addresses, timeout, row)
        row.update(http_status=status, resolved_ip=address, success=True)
    except Exception as exc:
        row["error"] = f"{type(exc).__name__}: {exc}"[:300]
    return row


def load_data() -> pd.DataFrame:
    if not DATA_FILE.exists():
        return pd.DataFrame(columns=FIELDS)
    try:
        frame = pd.read_csv(DATA_FILE)
        # Keep old data columns while adding the new phase-specific measurements.
        for field in FIELDS:
            if field not in frame.columns:
                frame[field] = pd.NA
        return frame
    except (OSError, pd.errors.ParserError):
        return pd.DataFrame(columns=FIELDS)


def save_rows(rows: list[dict]) -> None:
    DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
    old = load_data()
    new = pd.concat([old, pd.DataFrame(rows)], ignore_index=True, sort=False)
    new.to_csv(DATA_FILE, index=False)


st.set_page_config(page_title="IPv6 & Network Performance", page_icon="🌐", layout="wide")
st.title("🌐 IPv6 Addressing & Network Performance")
st.caption("Compare IPv4 and IPv6 DNS, TCP, TLS, and HTTPS response behavior on your network.")

with st.sidebar:
    st.header("Experiment setup")
    hosts_text = st.text_area("Hostnames (one per line)", "\n".join(DEFAULT_HOSTS), height=110,
                              help="Use hostnames only. Each should support HTTPS; some may not support both IP versions.")
    repetitions = st.slider("Repetitions", 1, 10, 3)
    timeout = st.slider("Timeout per connection (seconds)", 2, 15, 6)
    run = st.button("Run measurements", type="primary", use_container_width=True)
    st.caption("Each run tries IPv4 and IPv6 independently. Network policy, VPN, DNS, and server load affect results.")

if run:
    try:
        hosts = list(dict.fromkeys(valid_host(line) for line in hosts_text.splitlines() if line.strip()))
        if not hosts:
            st.error("Enter at least one hostname.")
            st.stop()
    except ValueError as exc:
        st.error(str(exc))
        st.stop()
    rows = []
    progress = st.progress(0, text="Starting measurements…")
    total = len(hosts) * repetitions * 2
    done = 0
    for repetition in range(1, repetitions + 1):
        for host in hosts:
            for label, family in (("IPv4", socket.AF_INET), ("IPv6", socket.AF_INET6)):
                result = run_one(host, label, family, float(timeout))
                result["repetition"] = repetition
                rows.append(result)
                done += 1
                progress.progress(done / total, text=f"{done}/{total}: {host} {label}")
    save_rows(rows)
    st.session_state["last_run"] = pd.DataFrame(rows)
    progress.empty()
    st.success(f"Saved {len(rows)} measurements to {DATA_FILE.name}.")

frame = load_data()
if frame.empty:
    st.info("No measurements yet. Choose hostnames and select **Run measurements**.")
    st.stop()

for field in ("dns_ms", "tcp_connect_ms", "tls_handshake_ms", "request_headers_ms", "https_ms"):
    frame[field] = pd.to_numeric(frame[field], errors="coerce")
frame["success"] = frame["success"].astype(str).str.lower().isin(["true", "1"])
frame["timestamp_utc"] = pd.to_datetime(frame["timestamp_utc"], errors="coerce", utc=True)

c1, c2, c3 = st.columns(3)
c1.metric("Total attempts", len(frame))
c2.metric("Completed HTTPS requests", f"{frame['success'].sum()} / {len(frame)}")
c3.metric("Hosts measured", frame["host"].nunique())

st.subheader("Compare performance")
metric_labels = {"DNS lookup": "dns_ms", "TCP connection setup": "tcp_connect_ms",
                 "TLS security handshake": "tls_handshake_ms", "Request to response headers": "request_headers_ms"}
metric = st.radio("Measurement stage", list(metric_labels), horizontal=True)
column = metric_labels[metric]
chart_data = frame.dropna(subset=[column]).copy()
if chart_data.empty:
    st.warning(f"No {metric.lower()} timings have been recorded yet. Failed attempts may not reach this stage.")
else:
    summary = chart_data.groupby(["host", "protocol"], as_index=False)[column].median()
    summary["Measurement (ms)"] = summary[column]
    chart = px.bar(summary, x="host", y="Measurement (ms)", color="protocol", barmode="group",
                   title=f"Median {metric.lower()} by host", labels={"host": "Host", "protocol": "IP version"},
                   color_discrete_map={"IPv4": "#3B82F6", "IPv6": "#8B5CF6"})
    st.plotly_chart(chart, use_container_width=True)
    if metric == "Request to response headers":
        st.caption("Includes network round trip and server time to return headers; it is not a full page load.")
    elif metric == "DNS lookup":
        st.caption("Measured using the operating system resolver; cached results may be very fast.")
    else:
        st.caption("Each timing covers only the named stage. Later stages are blank if an earlier stage fails.")

st.subheader("Connectivity summary")
summary = frame.groupby(["host", "protocol"], as_index=False).agg(
    attempts=("success", "size"), successes=("success", "sum"), median_dns_ms=("dns_ms", "median"),
    median_tcp_connect_ms=("tcp_connect_ms", "median"), median_tls_handshake_ms=("tls_handshake_ms", "median"),
    median_request_headers_ms=("request_headers_ms", "median"), last_resolved_ip=("resolved_ip", "last"),
    last_error=("error", "last"))
summary["success_rate"] = (summary["successes"] / summary["attempts"] * 100).round(1).astype(str) + "%"
st.dataframe(summary, use_container_width=True, hide_index=True)

with st.expander("Raw measurement records"):
    st.dataframe(frame.sort_values("timestamp_utc", ascending=False), use_container_width=True, hide_index=True)

csv = frame.to_csv(index=False).encode("utf-8")
st.download_button("Download all measurements as CSV", csv, file_name="ipv6_network_measurements.csv", mime="text/csv")

with st.expander("IPv6 address learning tool"):
    address = st.text_input("Enter an IPv6 address", placeholder="2001:db8::1")
    if address:
        try:
            parsed = ipaddress.IPv6Address(address.strip())
            a, b = st.columns(2)
            a.write(f"**Compressed:** `{parsed.compressed}`")
            b.write(f"**Expanded:** `{parsed.exploded}`")
            st.write(f"**Address type:** {'Loopback' if parsed.is_loopback else 'Link-local' if parsed.is_link_local else 'Multicast' if parsed.is_multicast else 'Private/unique local' if parsed.is_private else 'Global or other'}")
            st.write(f"**Integer value:** `{int(parsed)}`")
        except ipaddress.AddressValueError as exc:
            st.error(str(exc))

st.caption("Interpret results cautiously: this is a lightweight end-host experiment, not a controlled network benchmark. IPv4 and IPv6 routes may differ, and an unavailable family is a valid connectivity result rather than a speed of zero.")
