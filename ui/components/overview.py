"""
Overview page — WAN status, KPI cards, device type distribution, top bandwidth.
"""
from __future__ import annotations

from datetime import datetime

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from src.database_manager import DatabaseManager
from ui.components.theme import (
    DEVICE_COLORS, DEVICE_ICONS,
    fmt_bytes, fmt_bytes_rate, fmt_uptime,
    plotly_dark_layout, metric_card,
)


# ------------------------------------------------------------------
# Cached data loaders
# ------------------------------------------------------------------

@st.cache_data(ttl=30, show_spinner=False)
def _load_wan(_db: DatabaseManager) -> pd.DataFrame:
    return _db.get_latest_wan_status()


@st.cache_data(ttl=60, show_spinner=False)
def _load_stats(_db: DatabaseManager) -> dict:
    return _db.get_summary_stats(days=30)


@st.cache_data(ttl=60, show_spinner=False)
def _load_device_type_counts(_db: DatabaseManager) -> pd.DataFrame:
    return _db.get_device_type_counts()


@st.cache_data(ttl=60, show_spinner=False)
def _load_top_bandwidth(_db: DatabaseManager) -> pd.DataFrame:
    return _db.get_top_bandwidth_consumers(limit=5)


@st.cache_data(ttl=60, show_spinner=False)
def _load_latest_snapshots(_db: DatabaseManager) -> pd.DataFrame:
    return _db.get_latest_client_snapshots()


@st.cache_data(ttl=60, show_spinner=False)
def _load_vpn(_db: DatabaseManager) -> pd.DataFrame:
    return _db.get_vpn_status()


@st.cache_data(ttl=60, show_spinner=False)
def _load_system_uptime(_db: DatabaseManager) -> int | None:
    return _db.get_system_uptime()


@st.cache_data(ttl=60, show_spinner=False)
def _load_monthly_bytes(_db: DatabaseManager) -> dict:
    return _db.get_monthly_wan_bytes()


@st.cache_data(ttl=60, show_spinner=False)
def _load_wan_uptime(_db: DatabaseManager, year: int, month: int) -> dict:
    return _db.get_wan_uptime_stats(year, month)


@st.cache_data(ttl=300, show_spinner=False)
def _load_wan_throughput(_db: DatabaseManager) -> pd.DataFrame:
    return _db.get_wan_throughput_history(hours=24, interval="hourly")


# ------------------------------------------------------------------
# WAN section
# ------------------------------------------------------------------

def _render_wan(wan_df: pd.DataFrame) -> None:
    st.subheader("Status dos Links WAN")

    if wan_df.empty:
        st.info(
            "Nenhum dado de WAN coletado ainda.  "
            "Execute `python run.py collect-once` para iniciar."
        )
        return

    cols = st.columns(len(wan_df))
    for col, (_, row) in zip(cols, wan_df.iterrows()):
        is_ok   = str(row.get("status", "")).lower() == "ok"
        badge   = "🟢 Online" if is_ok else "🔴 Offline"
        iface   = row.get("interface", "WAN")
        lat     = row.get("latency_ms")
        lat_str = f"{int(lat)} ms" if pd.notna(lat) else "—"
        rx_str  = fmt_bytes_rate(row.get("rx_bytes"))
        tx_str  = fmt_bytes_rate(row.get("tx_bytes"))
        color   = "#3fb950" if is_ok else "#ff7b72"

        upt     = row.get("uptime")
        upt_str = fmt_uptime(upt) if upt else "—"

        with col:
            st.markdown(
                metric_card(
                    title    = iface,
                    value    = row.get("wan_ip") or "—",
                    subtitle = badge,
                    icon     = "🌐",
                    color    = color,
                ),
                unsafe_allow_html=True,
            )
            st.caption(f"Uptime: **{upt_str}** &nbsp;|&nbsp; Latência: **{lat_str}**")
            st.caption(f"↓ {rx_str}  ↑ {tx_str}")


# ------------------------------------------------------------------
# KPI section
# ------------------------------------------------------------------

def _render_kpis(stats: dict) -> None:
    st.subheader("Resumo — Últimos 30 dias")

    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("🚫 Bloqueios Totais",      stats.get("total_blocks", 0),       help="Firewall + Traffic Rules")
    c2.metric("👤 Infratores Únicos",     stats.get("unique_violators", 0),   help="Dispositivos distintos bloqueados")
    c3.metric("⚠️ Ameaças IPS/IDS",     stats.get("total_threats", 0),       help="Eventos IPS/IDS detectados")
    c4.metric("🔴 Suspeitos",            stats.get("suspicious_devices", 0),  help="Marcados pelo motor de auditoria")
    c5.metric("📡 Online Agora",          stats.get("online_devices", 0),      help="Dispositivos com snapshot nos últimos 5 min")


# ------------------------------------------------------------------
# Device type donut
# ------------------------------------------------------------------

def _render_device_donut(type_df: pd.DataFrame) -> None:
    if type_df.empty:
        st.info("Sem dados de classificação de dispositivos ainda.")
        return

    # Normalise None/null device_type
    type_df = type_df.copy()
    type_df["device_type"] = type_df["device_type"].fillna("unknown")

    labels = type_df["device_type"].tolist()
    values = type_df["count"].tolist()
    colors = [DEVICE_COLORS.get(lbl, "#484f58") for lbl in labels]
    icons  = [DEVICE_ICONS.get(lbl, "❓") for lbl in labels]
    display_labels = [f"{icons[i]} {lbl.capitalize()}" for i, lbl in enumerate(labels)]

    fig = go.Figure(go.Pie(
        labels       = display_labels,
        values       = values,
        hole         = 0.55,
        marker_colors= colors,
        textinfo     = "percent+label",
        textposition = "inside",
        insidetextorientation="radial",
        hovertemplate="<b>%{label}</b><br>Dispositivos: %{value}<br>%{percent}<extra></extra>",
    ))
    layout = plotly_dark_layout()
    layout.update({
        "title":         "Tipos de Dispositivos",
        "showlegend":    False,
        "height":        320,
        "margin":        {"t": 50, "b": 10, "l": 10, "r": 10},
    })
    fig.update_layout(**layout)
    st.plotly_chart(fig, use_container_width=True)


# ------------------------------------------------------------------
# Top bandwidth bar chart
# ------------------------------------------------------------------

def _render_top_bandwidth(bw_df: pd.DataFrame) -> None:
    if bw_df.empty:
        st.info("Sem dados de largura de banda. Execute o collector primeiro.")
        return

    df = bw_df.copy()
    df["label"]     = df["name"].fillna(df["mac"])
    df["tx_mb"]     = df["tx_bytes_rate"].fillna(0) / 1_000_000
    df["rx_mb"]     = df["rx_bytes_rate"].fillna(0) / 1_000_000
    df["tx_label"]  = df["tx_bytes_rate"].apply(fmt_bytes_rate)
    df["rx_label"]  = df["rx_bytes_rate"].apply(fmt_bytes_rate)

    df = df.sort_values("total_rate", ascending=True)

    fig = go.Figure()
    fig.add_trace(go.Bar(
        y           = df["label"],
        x           = df["rx_mb"],
        name        = "Download",
        orientation = "h",
        marker_color= "#58a6ff",
        hovertemplate="<b>%{y}</b><br>Download: %{customdata}<extra></extra>",
        customdata  = df["rx_label"],
    ))
    fig.add_trace(go.Bar(
        y           = df["label"],
        x           = df["tx_mb"],
        name        = "Upload",
        orientation = "h",
        marker_color= "#3fb950",
        hovertemplate="<b>%{y}</b><br>Upload: %{customdata}<extra></extra>",
        customdata  = df["tx_label"],
    ))

    layout = plotly_dark_layout()
    layout.update({
        "title":     "Top 5 Consumidores de Largura de Banda",
        "barmode":   "stack",
        "height":    320,
        "xaxis":     {"title": "MB/s", "gridcolor": "#1e3a5f", "zerolinecolor": "#1e3a5f"},
        "yaxis":     {"gridcolor": "#1e3a5f", "zerolinecolor": "#1e3a5f"},
        "legend":    {"orientation": "h", "y": 1.08},
        "margin":    {"t": 60, "b": 30, "l": 20, "r": 20},
    })
    fig.update_layout(**layout)
    st.plotly_chart(fig, use_container_width=True)


# ------------------------------------------------------------------
# WAN throughput 24h trend
# ------------------------------------------------------------------

def _render_wan_trend(db: DatabaseManager) -> None:
    st.subheader("Tendência WAN — Últimas 24h (por hora)")
    df = _load_wan_throughput(db)

    if df.empty:
        st.info(
            "Sem dados de throughput WAN histórico ainda.  "
            "Os dados serão coletados via `/stat/report/hourly.gw` nos próximos ciclos."
        )
        return

    df = df.copy()
    df["rx_mb"] = df["rx_bytes"] / 1_048_576
    df["tx_mb"] = df["tx_bytes"] / 1_048_576

    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=df["timestamp"], y=df["rx_mb"],
        name="Download",
        mode="lines+markers",
        line=dict(color="#58a6ff", width=2),
        fill="tozeroy",
        fillcolor="rgba(88,166,255,0.08)",
        hovertemplate="<b>%{x|%H:%M}</b><br>Download: %{y:.1f} MB<extra></extra>",
    ))
    fig.add_trace(go.Scatter(
        x=df["timestamp"], y=df["tx_mb"],
        name="Upload",
        mode="lines+markers",
        line=dict(color="#3fb950", width=2),
        hovertemplate="<b>%{x|%H:%M}</b><br>Upload: %{y:.1f} MB<extra></extra>",
    ))

    layout = plotly_dark_layout()
    layout.update({
        "height":  260,
        "xaxis":   {"title": "Hora", "gridcolor": "#1e3a5f", "zerolinecolor": "#1e3a5f"},
        "yaxis":   {"title": "MB por hora", "gridcolor": "#1e3a5f", "zerolinecolor": "#1e3a5f"},
        "legend":  {"orientation": "h", "y": 1.08},
        "margin":  {"t": 30, "b": 30, "l": 40, "r": 20},
        "showlegend": True,
    })
    fig.update_layout(**layout)
    st.plotly_chart(fig, use_container_width=True)


# ------------------------------------------------------------------
# WAN uptime gauge
# ------------------------------------------------------------------

def _render_uptime_gauge(db: DatabaseManager) -> None:
    now = datetime.utcnow()
    uptime_data = _load_wan_uptime(db, now.year, now.month)

    st.subheader(f"Uptime WAN — {now.strftime('%B %Y')}")

    pct = uptime_data.get("uptime_pct")
    if pct is None:
        st.info("Dados insuficientes para calcular o uptime deste mês.")
        return

    bar_color = "#3fb950" if pct >= 99 else "#ffa657" if pct >= 95 else "#ff7b72"

    col_gauge, col_detail = st.columns([1, 1])
    with col_gauge:
        fig = go.Figure(go.Indicator(
            mode   = "gauge+number",
            value  = pct,
            number = {"suffix": "%", "font": {"size": 40}},
            gauge  = {
                "axis": {"range": [0, 100]},
                "bar":  {"color": bar_color},
                "steps": [
                    {"range": [0,  95],  "color": "#ffe0e0"},
                    {"range": [95, 99],  "color": "#fff3cd"},
                    {"range": [99, 100], "color": "#e0ffe8"},
                ],
                "threshold": {
                    "line": {"color": "black", "width": 4},
                    "thickness": 0.75,
                    "value": 99.9,
                },
            },
            title = {"text": "Disponibilidade"},
        ))
        fig.update_layout(height=260, margin=dict(t=40, b=0, l=20, r=20))
        st.plotly_chart(fig, use_container_width=True)

    with col_detail:
        st.metric("Amostras Coletadas", uptime_data["total_samples"])
        st.metric("Amostras Online",    uptime_data["up_samples"])
        avg_lat = uptime_data.get("avg_latency_ms")
        st.metric("Latência Média", f"{avg_lat} ms" if avg_lat else "—")


# ------------------------------------------------------------------
# Last snapshot timestamp
# ------------------------------------------------------------------

def _render_snapshot_status(snap_df: pd.DataFrame) -> None:
    if snap_df.empty:
        st.caption("Última coleta de snapshot: nenhuma ainda")
        return
    if "timestamp" in snap_df.columns:
        last_ts = pd.to_datetime(snap_df["timestamp"]).max()
        age_sec = (datetime.utcnow() - last_ts.to_pydatetime()).total_seconds()
        if age_sec < 60:
            age_str = f"{int(age_sec)}s atrás"
        elif age_sec < 3600:
            age_str = f"{int(age_sec // 60)}min atrás"
        else:
            age_str = f"{int(age_sec // 3600)}h atrás"
        st.caption(f"Último snapshot: **{last_ts.strftime('%H:%M:%S')}** ({age_str})")


# ------------------------------------------------------------------
# Main render
# ------------------------------------------------------------------

def _render_system_bar(db: DatabaseManager) -> None:
    """System uptime, monthly WAN data and VPN status in one row."""
    uptime_sec   = _load_system_uptime(db)
    monthly      = _load_monthly_bytes(db)
    vpn_df       = _load_vpn(db)

    cols = st.columns(4)

    # System Uptime
    with cols[0]:
        st.markdown(
            metric_card("System Uptime", fmt_uptime(uptime_sec),
                        "UDM-Pro online", "⏱️", "#58a6ff"),
            unsafe_allow_html=True,
        )

    # Monthly Download
    with cols[1]:
        rx = monthly.get("rx_bytes", 0)
        st.markdown(
            metric_card("Download Mensal", fmt_bytes(rx),
                        "Mês atual (est.)", "⬇️", "#3fb950"),
            unsafe_allow_html=True,
        )

    # Monthly Upload
    with cols[2]:
        tx = monthly.get("tx_bytes", 0)
        st.markdown(
            metric_card("Upload Mensal", fmt_bytes(tx),
                        "Mês atual (est.)", "⬆️", "#ffa657"),
            unsafe_allow_html=True,
        )

    # VPN
    with cols[3]:
        if vpn_df.empty:
            vpn_val   = "—"
            vpn_sub   = "Sem dados de VPN"
            vpn_color = "#484f58"
        else:
            n_running = int((vpn_df["status"] == "running").sum())
            n_total   = len(vpn_df)
            vpn_val   = f"{n_running}/{n_total}"
            vpn_sub   = "túneis online" if n_total != 1 else "túnel online"
            vpn_color = "#3fb950" if n_running == n_total else (
                "#ffa657" if n_running > 0 else "#ff7b72"
            )
        st.markdown(
            metric_card("VPN", vpn_val, vpn_sub, "🔒", vpn_color),
            unsafe_allow_html=True,
        )

    # VPN — detalhe inline (sem expander, lista compacta por túnel)
    if not vpn_df.empty:
        with st.expander("Detalhes VPN", expanded=True):
            for _, row in vpn_df.iterrows():
                is_up  = str(row.get("status", "")).lower() == "running"
                badge  = "🟢 Online" if is_up else "🔴 Offline"
                name   = row.get("tunnel_name") or "—"
                rip    = row.get("remote_ip") or "—"
                upt    = fmt_uptime(row.get("uptime"))
                upt_part = f" &nbsp;|&nbsp; Uptime: {upt}" if upt != "—" else ""
                st.markdown(
                    f"**{name}** &nbsp; {badge}  \n"
                    f"<small>IP Remoto: {rip}{upt_part}</small>",
                    unsafe_allow_html=True,
                )


def render(db: DatabaseManager) -> None:
    st.header("Visão Geral da Rede")

    wan_df   = _load_wan(db)
    stats    = _load_stats(db)
    type_df  = _load_device_type_counts(db)
    bw_df    = _load_top_bandwidth(db)
    snap_df  = _load_latest_snapshots(db)

    # ── Row 1: WAN cards ──────────────────────────────────────────
    _render_wan(wan_df)

    st.divider()

    # ── Row 1b: System Uptime + Monthly data + VPN ────────────────
    _render_system_bar(db)

    st.divider()

    # ── Row 2: KPI cards ─────────────────────────────────────────
    _render_kpis(stats)

    st.divider()

    # ── Row 3: Charts ────────────────────────────────────────────
    col_donut, col_bw = st.columns([1, 1])
    with col_donut:
        _render_device_donut(type_df)
    with col_bw:
        _render_top_bandwidth(bw_df)

    _render_snapshot_status(snap_df)

    st.divider()

    # ── Row 4: WAN throughput 24h trend ──────────────────────────
    _render_wan_trend(db)

    st.divider()

    # ── Row 5: WAN uptime gauge ───────────────────────────────────
    _render_uptime_gauge(db)
