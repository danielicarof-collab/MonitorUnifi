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
    metric_card, plotly_dark_layout, status_badge,
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
        is_ok = row.get("status") == "ok"
        color = "#3fb950" if is_ok else "#ff7b72"
        badge_html = status_badge(is_ok)
        card_html = metric_card(
            title    = f"{row['interface']} — Link",
            value    = row.get("wan_ip") or "—",
            subtitle = (
                f"Latência: {row.get('latency_ms') or '—'} ms  |  "
                f"Uptime: {fmt_uptime(row.get('uptime'))}<br>"
                f"↓ {fmt_bytes(row.get('rx_bytes'))}  "
                f"↑ {fmt_bytes(row.get('tx_bytes'))}"
            ),
            icon  = "🌐",
            color = color,
        )
        with col:
            st.markdown(badge_html, unsafe_allow_html=True)
            st.markdown(card_html, unsafe_allow_html=True)


# ------------------------------------------------------------------
# KPI section
# ------------------------------------------------------------------

def _render_kpis(stats: dict) -> None:
    st.subheader("Resumo — Últimos 30 dias")

    c1, c2, c3, c4, c5 = st.columns(5)

    kpi_defs = [
        (c1, "Bloqueios Totais",      str(stats.get("total_blocks", 0)),       "Firewall + Traffic Rules",  "🚫", "#ff7b72"),
        (c2, "Infratores Únicos",     str(stats.get("unique_violators", 0)),   "Dispositivos distintos",    "👤", "#ffa657"),
        (c3, "Ameaças IPS/IDS",       str(stats.get("total_threats", 0)),      "Eventos detectados",        "⚠️", "#d2a8ff"),
        (c4, "Dispositivos Suspeitos",str(stats.get("suspicious_devices", 0)),"Motor de auditoria",        "🔴", "#f0883e"),
        (c5, "Online Agora",          str(stats.get("online_devices", 0)),     "Últimos 5 minutos",         "📡", "#3fb950"),
    ]

    for col, title, value, subtitle, icon, color in kpi_defs:
        with col:
            st.markdown(metric_card(title, value, subtitle, icon, color), unsafe_allow_html=True)


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
# WAN uptime gauge
# ------------------------------------------------------------------

def _render_uptime_gauge(db: DatabaseManager) -> None:
    now = datetime.utcnow()
    uptime_data = db.get_wan_uptime_stats(now.year, now.month)

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
            number = {"suffix": "%", "font": {"size": 40, "color": "#e2e8f0"}},
            gauge  = {
                "axis":      {"range": [0, 100], "tickcolor": "#94a3b8"},
                "bar":       {"color": bar_color},
                "bgcolor":   "rgba(13,17,23,1)",
                "bordercolor": "#1e3a5f",
                "steps": [
                    {"range": [0,   95],  "color": "rgba(255,123,114,0.15)"},
                    {"range": [95,  99],  "color": "rgba(255,166,87,0.15)"},
                    {"range": [99, 100],  "color": "rgba(63,185,80,0.15)"},
                ],
                "threshold": {
                    "line":      {"color": "#58a6ff", "width": 3},
                    "thickness": 0.75,
                    "value":     99.9,
                },
            },
            title  = {"text": "Disponibilidade", "font": {"color": "#94a3b8"}},
        ))
        layout = plotly_dark_layout()
        layout.update({"height": 260, "margin": {"t": 40, "b": 0, "l": 20, "r": 20}})
        fig.update_layout(**layout)
        st.plotly_chart(fig, use_container_width=True)

    with col_detail:
        st.markdown(metric_card("Amostras Coletadas", str(uptime_data["total_samples"]),
                                "", "🔢", "#58a6ff"), unsafe_allow_html=True)
        st.markdown(metric_card("Amostras Online", str(uptime_data["up_samples"]),
                                "", "✅", "#3fb950"), unsafe_allow_html=True)
        avg_lat = uptime_data.get("avg_latency_ms")
        lat_str = f"{avg_lat} ms" if avg_lat else "—"
        st.markdown(metric_card("Latência Média", lat_str, "", "📶", "#ffa657"),
                    unsafe_allow_html=True)


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

    # ── Row 4: WAN uptime gauge ───────────────────────────────────
    _render_uptime_gauge(db)
