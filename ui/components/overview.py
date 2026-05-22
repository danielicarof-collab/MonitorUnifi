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
    plotly_dark_layout, utc_to_local,
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
        badge = "🟢 Online" if is_ok else "🔴 Offline"
        with col:
            st.metric(
                label=f"**{row['interface']}** — {badge}",
                value=row.get("wan_ip") or "—",
                help="IP público atual",
            )
            st.caption(f"Latência: **{row.get('latency_ms') or '—'} ms**")
            st.caption(f"Uptime: **{fmt_uptime(row.get('uptime'))}**")
            st.caption(
                f"↓ {fmt_bytes(row.get('rx_bytes'))}  "
                f"↑ {fmt_bytes(row.get('tx_bytes'))}"
            )


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
    if bw_df["total_rate"].sum() == 0:
        st.info(
            "Dados de throughput em tempo real indisponíveis agora. "
            "Os campos `tx_bytes-r` / `rx_bytes-r` só ficam populados quando "
            "há tráfego ativo no momento da coleta — aguarde o próximo ciclo."
        )
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
        last_ts_utc = pd.to_datetime(snap_df["timestamp"]).max().to_pydatetime()
        last_ts_local = utc_to_local(last_ts_utc)
        age_sec = (datetime.utcnow() - last_ts_utc).total_seconds()
        if age_sec < 60:
            age_str = f"{int(age_sec)}s atrás"
        elif age_sec < 3600:
            age_str = f"{int(age_sec // 60)}min atrás"
        else:
            age_str = f"{int(age_sec // 3600)}h atrás"
        st.caption(f"Último snapshot: **{last_ts_local.strftime('%d/%m %H:%M:%S')}** ({age_str})")


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
