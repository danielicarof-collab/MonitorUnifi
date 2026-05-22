"""
Overview page — WAN status cards, traffic summary, VPN tunnels.
"""
from __future__ import annotations

import math
from datetime import datetime

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from src.database_manager import DatabaseManager


def _fmt_bytes(n: int | float | None) -> str:
    if n is None:
        return "—"
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def _fmt_uptime(seconds: int | None) -> str:
    if seconds is None:
        return "—"
    d, rem = divmod(int(seconds), 86400)
    h, rem = divmod(rem, 3600)
    m, _   = divmod(rem, 60)
    parts = []
    if d:
        parts.append(f"{d}d")
    if h:
        parts.append(f"{h}h")
    parts.append(f"{m}m")
    return " ".join(parts)


def _status_badge(status: str) -> str:
    return "🟢 Online" if status == "ok" else "🔴 Offline"


@st.cache_data(ttl=30, show_spinner=False)
def _load_wan(_db: DatabaseManager) -> pd.DataFrame:
    return _db.get_latest_wan_status()


@st.cache_data(ttl=30, show_spinner=False)
def _load_stats(_db: DatabaseManager) -> dict:
    return _db.get_summary_stats(days=30)


@st.cache_data(ttl=60, show_spinner=False)
def _load_wan_history(_db: DatabaseManager) -> pd.DataFrame:
    return _db.get_block_timeline(days=1)


def render(db: DatabaseManager) -> None:
    st.header("Visão Geral da Rede")

    wan_df = _load_wan(db)
    stats  = _load_stats(db)

    # ------------------------------------------------------------------
    # WAN interface cards
    # ------------------------------------------------------------------
    st.subheader("Status dos Links WAN")

    if wan_df.empty:
        st.info(
            "Nenhum dado de WAN coletado ainda.  "
            "Execute `python run.py collect-once` para iniciar."
        )
    else:
        cols = st.columns(len(wan_df))
        for col, (_, row) in zip(cols, wan_df.iterrows()):
            with col:
                st.metric(
                    label=f"**{row['interface']}** — {_status_badge(row['status'])}",
                    value=row.get("wan_ip") or "—",
                    help="IP público",
                )
                st.caption(f"Latência: **{row['latency_ms'] or '—'} ms**")
                st.caption(f"Uptime: **{_fmt_uptime(row.get('uptime'))}**")
                st.caption(
                    f"↓ {_fmt_bytes(row.get('rx_bytes'))}  "
                    f"↑ {_fmt_bytes(row.get('tx_bytes'))}"
                )

    st.divider()

    # ------------------------------------------------------------------
    # Summary KPI cards (last 30 days)
    # ------------------------------------------------------------------
    st.subheader("Resumo — Últimos 30 dias")

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("🚫 Bloqueios Totais",     stats["total_blocks"],       help="Firewall + Traffic Rules")
    c2.metric("👤 Infratores Únicos",    stats["unique_violators"],   help="Dispositivos únicos bloqueados")
    c3.metric("⚠️ Ameaças Detectadas",  stats["total_threats"],      help="IPS/IDS eventos")
    c4.metric("🔴 Dispositivos Suspeitos", stats["suspicious_devices"], help="Marcados pelo motor de auditoria")

    st.divider()

    # ------------------------------------------------------------------
    # WAN uptime gauge (current month)
    # ------------------------------------------------------------------
    now   = datetime.utcnow()
    uptime_data = db.get_wan_uptime_stats(now.year, now.month)

    st.subheader(f"Uptime WAN — {now.strftime('%B %Y')}")

    pct = uptime_data.get("uptime_pct")
    if pct is not None:
        col_gauge, col_detail = st.columns([1, 1])
        with col_gauge:
            fig = go.Figure(go.Indicator(
                mode="gauge+number",
                value=pct,
                number={"suffix": "%", "font": {"size": 40}},
                gauge={
                    "axis": {"range": [0, 100]},
                    "bar":  {"color": "#00cc66" if pct >= 99 else "#ff9900" if pct >= 95 else "#cc0000"},
                    "steps": [
                        {"range": [0,   95],  "color": "#ffe0e0"},
                        {"range": [95,  99],  "color": "#fff3cd"},
                        {"range": [99, 100],  "color": "#e0ffe8"},
                    ],
                    "threshold": {"line": {"color": "black", "width": 4}, "thickness": 0.75, "value": 99.9},
                },
                title={"text": "Disponibilidade"},
            ))
            fig.update_layout(height=250, margin=dict(t=40, b=0, l=20, r=20))
            st.plotly_chart(fig, use_container_width=True)

        with col_detail:
            st.metric("Amostras coletadas", uptime_data["total_samples"])
            st.metric("Amostras online",    uptime_data["up_samples"])
            avg_lat = uptime_data.get("avg_latency_ms")
            st.metric("Latência média", f"{avg_lat} ms" if avg_lat else "—")
    else:
        st.info("Dados insuficientes para calcular o uptime deste mês.")
