"""
Infrastructure page — AP stats, hardware health, speedtest, port stats, rogue APs.
"""
from __future__ import annotations

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from src.database_manager import DatabaseManager
from ui.components.theme import (
    fmt_bytes_rate, fmt_uptime, metric_card, plotly_dark_layout,
)


# ------------------------------------------------------------------
# Cached data loaders
# ------------------------------------------------------------------

@st.cache_data(ttl=60, show_spinner=False)
def _load_ap_stats(_db: DatabaseManager) -> pd.DataFrame:
    return _db.get_latest_ap_stats()


@st.cache_data(ttl=300, show_spinner=False)
def _load_firewall_rules(_db: DatabaseManager) -> pd.DataFrame:
    return _db.get_firewall_rules()


@st.cache_data(ttl=300, show_spinner=False)
def _load_port_forwards(_db: DatabaseManager) -> pd.DataFrame:
    return _db.get_port_forwards()


@st.cache_data(ttl=60, show_spinner=False)
def _load_rogue_aps(_db: DatabaseManager) -> pd.DataFrame:
    return _db.get_rogue_aps()


@st.cache_data(ttl=60, show_spinner=False)
def _load_device_stats(_db: DatabaseManager) -> pd.DataFrame:
    return _db.get_latest_device_stat()


@st.cache_data(ttl=60, show_spinner=False)
def _load_device_history(_db: DatabaseManager, mac: str, hours: int) -> pd.DataFrame:
    return _db.get_device_stats(mac, hours=hours)


@st.cache_data(ttl=300, show_spinner=False)
def _load_speedtest_history(_db: DatabaseManager) -> pd.DataFrame:
    return _db.get_speedtest_history(days=30)


@st.cache_data(ttl=60, show_spinner=False)
def _load_port_stats(_db: DatabaseManager, mac: str) -> pd.DataFrame:
    return _db.get_latest_port_stats(mac)


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _satisfaction_color(score: int | None) -> str:
    if score is None:
        return "#484f58"
    if score >= 80:
        return "#3fb950"
    if score >= 60:
        return "#ffa657"
    return "#ff7b72"


def _satisfaction_label(score: int | None) -> str:
    if score is None:
        return "—"
    if score >= 80:
        return f"🟢 {score}%"
    if score >= 60:
        return f"🟡 {score}%"
    return f"🔴 {score}%"


def _temp_color(temp: float | None) -> str:
    if temp is None:
        return "#484f58"
    if temp < 55:
        return "#3fb950"
    if temp < 70:
        return "#ffa657"
    return "#ff7b72"


def _cpu_color(pct: float | None) -> str:
    if pct is None:
        return "#484f58"
    if pct < 60:
        return "#3fb950"
    if pct < 85:
        return "#ffa657"
    return "#ff7b72"


def _ap_card(row: pd.Series) -> str:
    name  = row.get("name") or row.get("mac") or "AP"
    model = row.get("model") or "—"
    ip    = row.get("ip") or "—"
    sat   = row.get("satisfaction")
    sat_color = _satisfaction_color(sat)
    sat_label = _satisfaction_label(sat)

    clients_total = row.get("num_clients") or 0
    clients_24g   = row.get("num_clients_24g") or 0
    clients_5g    = row.get("num_clients_5g") or 0
    clients_6g    = row.get("num_clients_6g") or 0

    tx_rate = fmt_bytes_rate(row.get("tx_bytes_rate"))
    rx_rate = fmt_bytes_rate(row.get("rx_bytes_rate"))
    uptime  = fmt_uptime(row.get("uptime_sec"))

    ch_24g = row.get("channel_24g")
    ch_5g  = row.get("channel_5g")
    ch_str = ""
    if ch_24g:
        ch_str += f" 2.4GHz→ch{ch_24g}"
    if ch_5g:
        ch_str += f" 5GHz→ch{ch_5g}"

    return f"""
<div style="background:#111827; border:1px solid #1e3a5f; border-left:4px solid {sat_color};
     border-radius:12px; padding:18px 22px; margin:6px 0;
     box-shadow:0 4px 12px rgba(0,0,0,0.4);">
  <div style="display:flex; justify-content:space-between; align-items:flex-start;">
    <div>
      <div style="color:#e2e8f0; font-size:16px; font-weight:700;">{name}</div>
      <div style="color:#6b7280; font-size:12px; margin-top:2px;">
        {model} &nbsp;|&nbsp; {ip}
      </div>
    </div>
    <div style="text-align:right;">
      <div style="color:{sat_color}; font-size:18px; font-weight:700;">{sat_label}</div>
      <div style="color:#94a3b8; font-size:11px;">satisfação</div>
    </div>
  </div>
  <div style="margin-top:12px; display:grid; grid-template-columns:1fr 1fr; gap:8px;">
    <div style="background:#0d1117; border-radius:8px; padding:8px 12px;">
      <div style="color:#94a3b8; font-size:11px; text-transform:uppercase;">Clientes</div>
      <div style="color:#58a6ff; font-size:20px; font-weight:700;">{clients_total}</div>
      <div style="color:#6b7280; font-size:11px;">
        2.4G: {clients_24g} &nbsp;|&nbsp; 5G: {clients_5g}
        {f" &nbsp;|&nbsp; 6G: {clients_6g}" if clients_6g else ""}
      </div>
    </div>
    <div style="background:#0d1117; border-radius:8px; padding:8px 12px;">
      <div style="color:#94a3b8; font-size:11px; text-transform:uppercase;">Throughput</div>
      <div style="color:#3fb950; font-size:13px; font-weight:600;">↓ {rx_rate}</div>
      <div style="color:#ffa657; font-size:13px; font-weight:600;">↑ {tx_rate}</div>
    </div>
  </div>
  <div style="margin-top:8px; color:#6b7280; font-size:11px;">
    ⏱ Uptime: {uptime}
    {f' &nbsp;|&nbsp; 📻 Canais:{ch_str}' if ch_str else ''}
  </div>
</div>
"""


# ------------------------------------------------------------------
# Hardware health section
# ------------------------------------------------------------------

def _render_hardware_health(dev_df: pd.DataFrame, db: DatabaseManager) -> None:
    st.subheader("Saúde do Hardware (UDM-Pro / Switches)")

    if dev_df.empty:
        st.info(
            "Nenhum dado de hardware disponível.  "
            "Execute `python run.py collect-once` para coletar os dados."
        )
        return

    for _, row in dev_df.iterrows():
        name  = row.get("device_name") or row.get("device_mac")
        model = row.get("device_model") or "—"
        mac   = row.get("device_mac", "")
        cpu   = row.get("cpu_pct")
        mem   = row.get("memory_pct")
        t_cpu = row.get("temp_cpu")
        t_brd = row.get("temp_board")
        t_phy = row.get("temp_phy")
        up    = row.get("uptime_sec")

        cpu_str   = f"{cpu:.1f}%" if cpu is not None else "—"
        mem_str   = f"{mem:.1f}%" if mem is not None else "—"
        tcpu_str  = f"{t_cpu:.1f}°C" if t_cpu is not None else "—"
        tbrd_str  = f"{t_brd:.1f}°C" if t_brd is not None else "—"
        tphy_str  = f"{t_phy:.1f}°C" if t_phy is not None else "—"

        cpu_c = _cpu_color(cpu)
        mem_c = _cpu_color(mem)
        tc_c  = _temp_color(t_cpu)
        tb_c  = _temp_color(t_brd)
        tp_c  = _temp_color(t_phy)

        st.markdown(f"""
<div style="background:#111827; border:1px solid #1e3a5f; border-left:4px solid #58a6ff;
     border-radius:12px; padding:18px 22px; margin:6px 0 12px;
     box-shadow:0 4px 12px rgba(0,0,0,0.4);">
  <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:14px;">
    <div>
      <div style="color:#e2e8f0; font-size:16px; font-weight:700;">🖥️ {name}</div>
      <div style="color:#6b7280; font-size:12px;">{model} &nbsp;|&nbsp; {mac} &nbsp;|&nbsp; ⏱ {fmt_uptime(up)}</div>
    </div>
  </div>
  <div style="display:grid; grid-template-columns:repeat(5,1fr); gap:10px;">
    <div style="background:#0d1117; border-radius:8px; padding:10px; text-align:center;">
      <div style="color:#94a3b8; font-size:11px; margin-bottom:4px;">CPU</div>
      <div style="color:{cpu_c}; font-size:22px; font-weight:700;">{cpu_str}</div>
    </div>
    <div style="background:#0d1117; border-radius:8px; padding:10px; text-align:center;">
      <div style="color:#94a3b8; font-size:11px; margin-bottom:4px;">Memória</div>
      <div style="color:{mem_c}; font-size:22px; font-weight:700;">{mem_str}</div>
    </div>
    <div style="background:#0d1117; border-radius:8px; padding:10px; text-align:center;">
      <div style="color:#94a3b8; font-size:11px; margin-bottom:4px;">Temp CPU</div>
      <div style="color:{tc_c}; font-size:22px; font-weight:700;">{tcpu_str}</div>
    </div>
    <div style="background:#0d1117; border-radius:8px; padding:10px; text-align:center;">
      <div style="color:#94a3b8; font-size:11px; margin-bottom:4px;">Temp Board</div>
      <div style="color:{tb_c}; font-size:22px; font-weight:700;">{tbrd_str}</div>
    </div>
    <div style="background:#0d1117; border-radius:8px; padding:10px; text-align:center;">
      <div style="color:#94a3b8; font-size:11px; margin-bottom:4px;">Temp PHY</div>
      <div style="color:{tp_c}; font-size:22px; font-weight:700;">{tphy_str}</div>
    </div>
  </div>
</div>
""", unsafe_allow_html=True)

        # Historical chart for this device
        if mac:
            hours = st.select_slider(
                f"Histórico — {name}",
                options=[1, 3, 6, 12, 24, 48, 72],
                value=24,
                key=f"hw_hours_{mac}",
            )
            hist = _load_device_history(db, mac, hours)
            if not hist.empty and hist["cpu_pct"].notna().any():
                fig = go.Figure()
                if hist["cpu_pct"].notna().any():
                    fig.add_trace(go.Scatter(
                        x=hist["timestamp"], y=hist["cpu_pct"],
                        name="CPU %", mode="lines",
                        line=dict(color="#58a6ff", width=2),
                        fill="tozeroy", fillcolor="rgba(88,166,255,0.1)",
                    ))
                if hist["memory_pct"].notna().any():
                    fig.add_trace(go.Scatter(
                        x=hist["timestamp"], y=hist["memory_pct"],
                        name="Memória %", mode="lines",
                        line=dict(color="#ffa657", width=2),
                    ))
                if hist["temp_cpu"].notna().any():
                    fig.add_trace(go.Scatter(
                        x=hist["timestamp"], y=hist["temp_cpu"],
                        name="Temp CPU °C", mode="lines",
                        line=dict(color="#ff7b72", width=2),
                        yaxis="y2",
                    ))

                layout = plotly_dark_layout()
                layout.update({
                    "title":  f"CPU / Memória / Temperatura — últimas {hours}h",
                    "height": 280,
                    "xaxis":  {"gridcolor": "#1e3a5f", "zerolinecolor": "#1e3a5f"},
                    "yaxis":  {"title": "%", "range": [0, 100], "gridcolor": "#1e3a5f"},
                    "yaxis2": {
                        "title": "°C", "overlaying": "y", "side": "right",
                        "showgrid": False, "range": [20, 90],
                    },
                    "legend": {"orientation": "h", "y": 1.05},
                })
                fig.update_layout(**layout)
                st.plotly_chart(fig, use_container_width=True)


# ------------------------------------------------------------------
# Speedtest history section
# ------------------------------------------------------------------

def _render_speedtest(db: DatabaseManager) -> None:
    st.subheader("Histórico de Speedtest ISP")

    df = _load_speedtest_history(db)
    if df.empty:
        st.info("Nenhum resultado de speedtest disponível ainda.")
        return

    latest = df.iloc[-1]
    col1, col2, col3 = st.columns(3)
    with col1:
        dl = latest.get("download_mbps")
        st.markdown(
            metric_card("Download", f"{dl:.1f} Mbps" if dl else "—",
                        "Último speedtest", "⬇️", "#3fb950"),
            unsafe_allow_html=True,
        )
    with col2:
        ul = latest.get("upload_mbps")
        st.markdown(
            metric_card("Upload", f"{ul:.1f} Mbps" if ul else "—",
                        "Último speedtest", "⬆️", "#ffa657"),
            unsafe_allow_html=True,
        )
    with col3:
        ping = latest.get("ping_ms")
        st.markdown(
            metric_card("Ping", f"{ping:.0f} ms" if ping else "—",
                        "Último speedtest", "📡", "#58a6ff"),
            unsafe_allow_html=True,
        )

    if len(df) >= 2:
        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=df["timestamp"], y=df["download_mbps"],
            name="Download Mbps", mode="lines+markers",
            line=dict(color="#3fb950", width=2),
            fill="tozeroy", fillcolor="rgba(63,185,80,0.08)",
        ))
        fig.add_trace(go.Scatter(
            x=df["timestamp"], y=df["upload_mbps"],
            name="Upload Mbps", mode="lines+markers",
            line=dict(color="#ffa657", width=2),
        ))
        fig.add_trace(go.Scatter(
            x=df["timestamp"], y=df["ping_ms"],
            name="Ping ms", mode="lines+markers",
            line=dict(color="#58a6ff", width=1, dash="dot"),
            yaxis="y2",
        ))

        layout = plotly_dark_layout()
        layout.update({
            "title":  "Velocidade ISP ao longo do tempo",
            "height": 300,
            "xaxis":  {"gridcolor": "#1e3a5f"},
            "yaxis":  {"title": "Mbps", "gridcolor": "#1e3a5f"},
            "yaxis2": {
                "title": "ms", "overlaying": "y", "side": "right",
                "showgrid": False,
            },
            "legend": {"orientation": "h", "y": 1.05},
        })
        fig.update_layout(**layout)
        st.plotly_chart(fig, use_container_width=True)


# ------------------------------------------------------------------
# Port statistics section
# ------------------------------------------------------------------

def _render_port_stats(dev_df: pd.DataFrame, db: DatabaseManager) -> None:
    if dev_df.empty:
        return

    st.subheader("Estatísticas por Porta")

    for _, row in dev_df.iterrows():
        mac  = row.get("device_mac", "")
        name = row.get("device_name") or mac
        if not mac:
            continue

        ports = _load_port_stats(db, mac)
        if ports.empty:
            continue

        with st.expander(f"🔌 {name} — {len(ports)} portas", expanded=False):
            display = ports.copy()

            def _fmt_bytes(v):
                if v is None or (isinstance(v, float) and pd.isna(v)):
                    return "—"
                gb = v / 1_073_741_824
                if gb >= 1:
                    return f"{gb:.2f} GB"
                mb = v / 1_048_576
                if mb >= 1:
                    return f"{mb:.1f} MB"
                return f"{int(v / 1024)} KB"

            display["Status"]   = display["is_up"].apply(lambda u: "🟢 UP" if u else "🔴 DOWN")
            display["Velocidade"] = display["speed"].apply(lambda s: f"{s} Mbps" if s else "—")
            display["RX Total"] = display["rx_bytes"].apply(_fmt_bytes)
            display["TX Total"] = display["tx_bytes"].apply(_fmt_bytes)
            display["RX Rate"]  = display["rx_bytes_rate"].apply(fmt_bytes_rate)
            display["TX Rate"]  = display["tx_bytes_rate"].apply(fmt_bytes_rate)

            err_cols = []
            if display["rx_errors"].notna().any() or display["tx_errors"].notna().any():
                display["Erros RX"] = display["rx_errors"].fillna(0).astype(int)
                display["Erros TX"] = display["tx_errors"].fillna(0).astype(int)
                err_cols = ["Erros RX", "Erros TX"]

            poe_col = []
            if display["poe_power_w"].notna().any():
                display["PoE (W)"] = display["poe_power_w"].apply(
                    lambda v: f"{v:.1f}W" if v else "—"
                )
                poe_col = ["PoE (W)"]

            show_cols = (
                ["port_name", "Status", "Velocidade",
                 "RX Total", "TX Total", "RX Rate", "TX Rate"]
                + err_cols + poe_col
            )
            st.dataframe(
                display[show_cols].rename(columns={"port_name": "Porta"}),
                use_container_width=True,
                hide_index=True,
            )


# ------------------------------------------------------------------
# AP cards section
# ------------------------------------------------------------------

def _render_ap_cards(ap_df: pd.DataFrame) -> None:
    st.subheader("Access Points / Switches")

    if ap_df.empty:
        st.info(
            "Nenhuma estatística de AP disponível.  "
            "Execute `python run.py collect-once` para coletar dados dos dispositivos."
        )
        return

    col_a, col_b = st.columns(2)
    for i, (_, row) in enumerate(ap_df.iterrows()):
        col = col_a if i % 2 == 0 else col_b
        with col:
            st.markdown(_ap_card(row), unsafe_allow_html=True)


# ------------------------------------------------------------------
# Client distribution bar chart
# ------------------------------------------------------------------

def _render_client_distribution(ap_df: pd.DataFrame) -> None:
    if ap_df.empty or ap_df["num_clients"].sum() == 0:
        return

    st.subheader("Distribuição de Clientes por AP")

    df = ap_df.copy()
    df["AP"] = df["name"].fillna(df["mac"])
    df = df.sort_values("num_clients", ascending=False)

    fig = go.Figure()
    fig.add_trace(go.Bar(
        x=df["AP"], y=df["num_clients_24g"].fillna(0),
        name="2.4 GHz", marker_color="#ffa657",
    ))
    fig.add_trace(go.Bar(
        x=df["AP"], y=df["num_clients_5g"].fillna(0),
        name="5 GHz", marker_color="#58a6ff",
    ))
    if df["num_clients_6g"].sum() > 0:
        fig.add_trace(go.Bar(
            x=df["AP"], y=df["num_clients_6g"].fillna(0),
            name="6 GHz", marker_color="#d2a8ff",
        ))

    layout = plotly_dark_layout()
    layout.update({
        "title":   "Clientes por AP e Banda",
        "barmode": "stack",
        "height":  320,
        "xaxis":   {"title": "Access Point", "gridcolor": "#1e3a5f", "zerolinecolor": "#1e3a5f"},
        "yaxis":   {"title": "Clientes", "gridcolor": "#1e3a5f", "zerolinecolor": "#1e3a5f"},
        "legend":  {"orientation": "h", "y": 1.08},
    })
    fig.update_layout(**layout)
    st.plotly_chart(fig, use_container_width=True)


# ------------------------------------------------------------------
# Rogue APs section
# ------------------------------------------------------------------

def _render_rogue_aps(rogue_df: pd.DataFrame) -> None:
    st.subheader("APs Vizinhos Detectados")

    if rogue_df.empty:
        st.success("Nenhum AP vizinho/rogue detectado pelos seus APs gerenciados.")
        return

    rogue_count  = rogue_df["is_rogue"].sum() if "is_rogue" in rogue_df.columns else 0
    neighbor_cnt = len(rogue_df) - rogue_count

    c1, c2 = st.columns(2)
    with c1:
        st.markdown(
            metric_card("APs Rogues", str(int(rogue_count)),
                        "Detectados como rogue", "⚠️", "#ff7b72"),
            unsafe_allow_html=True,
        )
    with c2:
        st.markdown(
            metric_card("APs Vizinhos", str(int(neighbor_cnt)),
                        "Redes adjacentes", "📡", "#ffa657"),
            unsafe_allow_html=True,
        )

    display = rogue_df.copy()
    display["Rogue"] = display["is_rogue"].apply(lambda v: "⚠️ Sim" if v else "Vizinho")
    display["Sinal"] = display["signal"].apply(
        lambda s: f"{s} dBm" if s is not None else "—"
    )
    display["Detectado Por"] = display["ap_mac"].fillna("—")
    display["1ª Detecção"]   = pd.to_datetime(display["first_seen"]).dt.strftime("%d/%m %H:%M")
    display["Última Vez"]    = pd.to_datetime(display["last_seen"]).dt.strftime("%d/%m %H:%M")

    st.dataframe(
        display[[
            "Rogue", "ssid", "bssid", "channel", "Sinal",
            "security", "Detectado Por", "1ª Detecção", "Última Vez"
        ]].rename(columns={
            "ssid":     "SSID",
            "bssid":    "BSSID",
            "channel":  "Canal",
            "security": "Segurança",
        }),
        use_container_width=True,
        hide_index=True,
    )


# ------------------------------------------------------------------
# Firewall Rules section
# ------------------------------------------------------------------

def _render_firewall_rules(db: DatabaseManager) -> None:
    st.subheader("Regras de Firewall Configuradas")

    df = _load_firewall_rules(db)
    if df.empty:
        st.info("Nenhuma regra de firewall coletada ainda.")
        return

    total   = len(df)
    enabled = int(df["enabled"].sum()) if "enabled" in df.columns else total

    c1, c2 = st.columns(2)
    with c1:
        st.markdown(
            metric_card("Regras Total", str(total), "Firewall configurado", "🛡️", "#58a6ff"),
            unsafe_allow_html=True,
        )
    with c2:
        st.markdown(
            metric_card("Regras Ativas", str(enabled), f"{total - enabled} desativadas", "✅", "#3fb950"),
            unsafe_allow_html=True,
        )

    # Group by ruleset
    rulesets = df["ruleset"].dropna().unique().tolist()
    if not rulesets:
        rulesets = ["(sem grupo)"]

    tab_labels = sorted(rulesets) if rulesets else ["Todas"]
    tabs = st.tabs(tab_labels)
    for tab, ruleset in zip(tabs, tab_labels):
        with tab:
            subset = df[df["ruleset"] == ruleset].copy() if ruleset != "(sem grupo)" else df.copy()
            if subset.empty:
                st.caption("Nenhuma regra neste grupo.")
                continue

            subset["Status"]   = subset["enabled"].apply(lambda v: "✅ Ativa" if v else "⏸️ Desativada")
            subset["Ação"]     = subset["action"].str.upper().fillna("—")
            subset["Protocolo"]= subset["protocol"].fillna("all")
            subset["Origem"]   = subset["src_address"].fillna("any")
            subset["Destino"]  = subset["dst_address"].fillna("any")

            display_cols = ["rule_index", "name", "Status", "Ação", "Protocolo",
                            "Origem", "src_port", "Destino", "dst_port"]
            existing = [c for c in display_cols if c in subset.columns]
            st.dataframe(
                subset[existing].rename(columns={
                    "rule_index": "#",
                    "name":       "Nome",
                    "src_port":   "Porta Orig.",
                    "dst_port":   "Porta Dest.",
                }).fillna("—"),
                use_container_width=True,
                hide_index=True,
            )


# ------------------------------------------------------------------
# Port Forwards section
# ------------------------------------------------------------------

def _render_port_forwards(db: DatabaseManager) -> None:
    st.subheader("Port Forwarding")

    df = _load_port_forwards(db)
    if df.empty:
        st.info("Nenhuma regra de port forwarding coletada ainda.")
        return

    total   = len(df)
    enabled = int(df["enabled"].sum()) if "enabled" in df.columns else total

    c1, c2 = st.columns(2)
    with c1:
        st.markdown(
            metric_card("Regras Total", str(total), "Port forwards", "🔀", "#ffa657"),
            unsafe_allow_html=True,
        )
    with c2:
        st.markdown(
            metric_card("Ativas", str(enabled), f"{total - enabled} desativadas", "✅", "#3fb950"),
            unsafe_allow_html=True,
        )

    display = df.copy()
    display["Status"]   = display["enabled"].apply(lambda v: "✅" if v else "⏸️")
    display["Log"]      = display["log"].apply(lambda v: "📝 Sim" if v else "—")
    display["Protocolo"]= display["proto"].fillna("tcp")

    st.dataframe(
        display[[
            "Status", "name", "Protocolo", "src_port",
            "fwd_ip", "fwd_port", "Log",
        ]].rename(columns={
            "name":     "Nome",
            "src_port": "Porta Externa",
            "fwd_ip":   "IP Interno",
            "fwd_port": "Porta Interna",
        }).fillna("—"),
        use_container_width=True,
        hide_index=True,
    )


# ------------------------------------------------------------------
# Main render
# ------------------------------------------------------------------

def render(db: DatabaseManager) -> None:
    st.header("Infraestrutura de Rede")

    ap_df  = _load_ap_stats(db)
    dev_df = _load_device_stats(db)
    rogue_df = _load_rogue_aps(db)

    total_aps     = len(ap_df)
    total_clients = int(ap_df["num_clients"].sum()) if not ap_df.empty else 0
    avg_sat       = int(ap_df["satisfaction"].mean()) if not ap_df.empty and ap_df["satisfaction"].notna().any() else None

    c1, c2, c3 = st.columns(3)
    with c1:
        st.markdown(
            metric_card("APs Gerenciados", str(total_aps), "Dispositivos UniFi", "🔧", "#58a6ff"),
            unsafe_allow_html=True,
        )
    with c2:
        st.markdown(
            metric_card("Clientes Conectados", str(total_clients), "Total atual", "👥", "#3fb950"),
            unsafe_allow_html=True,
        )
    with c3:
        sat_str   = f"{avg_sat}%" if avg_sat is not None else "—"
        sat_color = "#3fb950" if avg_sat and avg_sat >= 80 else "#ffa657" if avg_sat and avg_sat >= 60 else "#ff7b72"
        st.markdown(
            metric_card("Satisfação Média", sat_str, "Score UniFi (0–100)", "📊", sat_color),
            unsafe_allow_html=True,
        )

    st.divider()
    _render_hardware_health(dev_df, db)

    st.divider()
    _render_speedtest(db)

    st.divider()
    _render_port_stats(dev_df, db)

    st.divider()
    _render_ap_cards(ap_df)

    if not ap_df.empty:
        st.divider()
        _render_client_distribution(ap_df)

    st.divider()
    _render_rogue_aps(rogue_df)

    st.divider()
    _render_firewall_rules(db)

    st.divider()
    _render_port_forwards(db)
