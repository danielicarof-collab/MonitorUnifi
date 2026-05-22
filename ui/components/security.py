"""
Security page — threat timeline, IPS events, suspicious-device alerts.
"""
from __future__ import annotations

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from src.database_manager import DatabaseManager

_SEVERITY_COLOR = {
    "critical": "#d62728",
    "high":     "#ff7f0e",
    "medium":   "#ffbb78",
    "low":      "#aec7e8",
}

_SEVERITY_EMOJI = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🔵",
}


@st.cache_data(ttl=60, show_spinner=False)
def _load_threats(_db: DatabaseManager, days: int) -> pd.DataFrame:
    return _db.get_threat_timeline(days=days)


@st.cache_data(ttl=60, show_spinner=False)
def _load_top_threats(_db: DatabaseManager, days: int) -> pd.DataFrame:
    return _db.get_top_threats(days=days, limit=20)


@st.cache_data(ttl=60, show_spinner=False)
def _load_block_timeline(_db: DatabaseManager, days: int) -> pd.DataFrame:
    return _db.get_block_timeline(days=days)


@st.cache_data(ttl=60, show_spinner=False)
def _load_suspicious(_db: DatabaseManager) -> pd.DataFrame:
    return _db.get_suspicious_clients()


def render(db: DatabaseManager) -> None:
    st.header("Segurança & Ameaças")

    days = st.selectbox("Janela de análise", [1, 3, 7, 14, 30], index=2, format_func=lambda x: f"{x} dias")

    # ------------------------------------------------------------------
    # Suspicious device alert banner
    # ------------------------------------------------------------------
    sus_df = _load_suspicious(db)
    if not sus_df.empty:
        with st.container():
            st.error(
                f"⚠️ **{len(sus_df)} dispositivo(s) marcado(s) como SUSPEITO** "
                f"— detectados por burst de bloqueios. Veja a seção abaixo."
            )

    # ------------------------------------------------------------------
    # Block + Threat volume timeline
    # ------------------------------------------------------------------
    st.subheader("Volume de Bloqueios ao Longo do Tempo")

    block_df  = _load_block_timeline(db, days)
    threat_df = _load_threats(db, days)

    if block_df.empty and threat_df.empty:
        st.info("Nenhum dado de segurança no período selecionado.")
    else:
        # Resample to hourly counts for readability
        def _hourly(df: pd.DataFrame, ts_col: str, label: str) -> pd.DataFrame:
            if df.empty:
                return pd.DataFrame(columns=["hora", "count", "series"])
            tmp = df[[ts_col]].copy()
            tmp["hora"] = pd.to_datetime(tmp[ts_col]).dt.floor("h")
            counts = tmp.groupby("hora").size().reset_index(name="count")
            counts["series"] = label
            return counts

        blocks_hourly  = _hourly(block_df,  "timestamp", "Bloqueios")
        threats_hourly = _hourly(threat_df, "timestamp", "Ameaças IPS")

        combined = pd.concat([blocks_hourly, threats_hourly], ignore_index=True)

        if not combined.empty:
            fig = px.bar(
                combined,
                x="hora",
                y="count",
                color="series",
                barmode="group",
                color_discrete_map={"Bloqueios": "#1f77b4", "Ameaças IPS": "#d62728"},
                labels={"hora": "Hora", "count": "Eventos", "series": ""},
                title="Eventos de Segurança por Hora",
            )
            fig.update_layout(legend=dict(orientation="h", y=1.05), margin=dict(t=60))
            st.plotly_chart(fig, use_container_width=True)

    st.divider()

    # ------------------------------------------------------------------
    # Threat severity distribution
    # ------------------------------------------------------------------
    st.subheader("Distribuição por Severidade")

    if not threat_df.empty:
        sev_counts = threat_df.groupby("severity").size().reset_index(name="count")
        sev_counts["color"] = sev_counts["severity"].map(_SEVERITY_COLOR)

        col_sev, col_sev_table = st.columns([1, 1])
        with col_sev:
            fig2 = go.Figure(go.Bar(
                x=sev_counts["severity"],
                y=sev_counts["count"],
                marker_color=sev_counts["color"],
                text=sev_counts["count"],
                textposition="outside",
            ))
            fig2.update_layout(
                xaxis_title="Severidade",
                yaxis_title="Total de Ameaças",
                showlegend=False,
                margin=dict(t=10),
            )
            st.plotly_chart(fig2, use_container_width=True)

        with col_sev_table:
            st.dataframe(
                sev_counts.drop(columns="color").rename(columns={
                    "severity": "Severidade",
                    "count":    "Eventos",
                }),
                use_container_width=True,
                hide_index=True,
            )
    else:
        st.info("Nenhuma ameaça IPS/IDS registrada neste período.")

    st.divider()

    # ------------------------------------------------------------------
    # Top threat events table
    # ------------------------------------------------------------------
    st.subheader("Últimos Eventos de Ameaça")

    top_df = _load_top_threats(db, days)
    if not top_df.empty:
        # Add severity emoji column for visual weight
        top_df.insert(
            0, "🚨",
            top_df["severity"].map(lambda s: _SEVERITY_EMOJI.get(s, "❓"))
        )
        st.dataframe(
            top_df.rename(columns={
                "timestamp":   "Hora",
                "client_name": "Origem",
                "threat_type": "Tipo",
                "severity":    "Severidade",
                "description": "Descrição",
                "action":      "Ação",
            }),
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info("Nenhum evento de ameaça no período.")

    st.divider()

    # ------------------------------------------------------------------
    # Suspicious devices detail
    # ------------------------------------------------------------------
    st.subheader("Dispositivos Suspeitos")
    st.caption(
        "Marcados automaticamente quando um dispositivo dispara múltiplos "
        "bloqueios em menos de 1 minuto."
    )

    if sus_df.empty:
        st.success("Nenhum dispositivo suspeito detectado.")
    else:
        for _, row in sus_df.iterrows():
            with st.expander(f"🔴 {row['name']} — {row['ip'] or 'IP desconhecido'}"):
                st.markdown(f"**MAC:** `{row['mac']}`")
                st.markdown(f"**Total de bloqueios:** {row['total_blocks']}")
                st.markdown(f"**Motivo:** {row['reason']}")
                st.markdown(f"**Último visto:** {row['last_seen']}")
