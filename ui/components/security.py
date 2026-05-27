"""
Security page — threat timeline, IPS events, suspicious devices, rogue APs.
"""
from __future__ import annotations

import os

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from src.ai_analyzer import ThreatAnalyzer
from src.database_manager import DatabaseManager
from ui.components.theme import metric_card, plotly_dark_layout

_SEVERITY_COLOR = {
    "critical": "#ff7b72",
    "high":     "#ffa657",
    "medium":   "#e3b341",
    "low":      "#58a6ff",
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


@st.cache_data(ttl=60, show_spinner=False)
def _load_rogue_aps(_db: DatabaseManager) -> pd.DataFrame:
    return _db.get_rogue_aps()


@st.cache_data(ttl=300, show_spinner=False)
def _load_ai_analysis(_db: DatabaseManager, days: int) -> dict | None:
    """Call Claude API to analyze current security posture. Cached 5 min."""
    try:
        analyzer = ThreatAnalyzer()
    except ValueError:
        return None  # ANTHROPIC_API_KEY not set
    stats     = _db.get_summary_stats(days=1)
    threat_df = _db.get_top_threats(days=1, limit=10)
    sus_df    = _db.get_suspicious_clients()
    top_threats = threat_df.to_dict("records") if not threat_df.empty else []
    return analyzer.analyze(
        stats            = stats,
        threat_count     = stats.get("total_threats", 0),
        suspicious_count = len(sus_df),
        top_threats      = top_threats,
    )


def _render_ai_analysis(analysis: dict | None) -> None:
    """Render the AI analysis card."""
    _SEV_COLOR = {
        "crítica": "#ff7b72",
        "alta":    "#ffa657",
        "média":   "#e3b341",
        "baixa":   "#58a6ff",
    }
    _SEV_DOT = {
        "crítica": "🔴",
        "alta":    "🟠",
        "média":   "🟡",
        "baixa":   "🔵",
    }

    if analysis is None:
        has_key = bool(os.getenv("ANTHROPIC_API_KEY"))
        msg = (
            "Configure <code>ANTHROPIC_API_KEY</code> no arquivo <code>.env</code> para ativar."
            if not has_key
            else "Aguardando dados suficientes para análise."
        )
        st.markdown(
            f"""<div style="background:#111827;border:1px solid #1e3a5f;border-left:4px solid #484f58;
            border-radius:12px;padding:16px 20px;margin:4px 0;">
              <div style="color:#94a3b8;font-size:11px;font-weight:700;text-transform:uppercase;
                   letter-spacing:0.1em;margin-bottom:10px;">🤖 Análise da IA</div>
              <div style="color:#6b7280;font-size:13px;">{msg}</div>
            </div>""",
            unsafe_allow_html=True,
        )
        return

    sev   = analysis.get("severidade", "baixa").lower()
    nivel = analysis.get("nivel", "N1")
    conf  = analysis.get("confianca", 0)
    color = _SEV_COLOR.get(sev, "#484f58")
    dot   = _SEV_DOT.get(sev, "⚪")
    resumo       = analysis.get("resumo", "")
    recomendacao = analysis.get("recomendacao", "")

    st.markdown(
        f"""<div style="background:#111827;border:1px solid #1e3a5f;border-left:4px solid {color};
        border-radius:12px;padding:16px 20px;margin:4px 0;
        box-shadow:0 4px 12px rgba(0,0,0,0.4);">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">
            <div style="color:#94a3b8;font-size:11px;font-weight:700;text-transform:uppercase;
                 letter-spacing:0.1em;">🤖 Análise da IA</div>
            <div style="display:flex;align-items:center;gap:12px;">
              <span style="background:#1e2a3a;border:1px solid {color};border-radius:20px;
                   padding:3px 12px;font-size:12px;color:{color};font-weight:600;">
                {dot} {sev.capitalize()} · {nivel}
              </span>
              <span style="color:#94a3b8;font-size:12px;">confiança: <b style="color:{color};">{conf}%</b></span>
            </div>
          </div>
          <div style="color:#e2e8f0;font-size:13px;margin-bottom:8px;">{resumo}</div>
          <div style="color:#94a3b8;font-size:12px;">
            <b style="color:{color};">→</b> {recomendacao}
          </div>
        </div>""",
        unsafe_allow_html=True,
    )


def render(db: DatabaseManager) -> None:
    st.header("Segurança & Ameaças")

    # AI Analysis card
    ai_result = _load_ai_analysis(db, 1)
    _render_ai_analysis(ai_result)

    st.divider()

    days = st.selectbox(
        "Janela de análise", [1, 3, 7, 14, 30], index=2,
        format_func=lambda x: f"{x} dias"
    )

    # ------------------------------------------------------------------
    # Suspicious device alert banner
    # ------------------------------------------------------------------
    sus_df = _load_suspicious(db)
    if not sus_df.empty:
        st.error(
            f"⚠️ **{len(sus_df)} dispositivo(s) marcado(s) como SUSPEITO** "
            "— detectados por burst de bloqueios. Veja a seção abaixo."
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
            fig = go.Figure()
            for series, color in [("Bloqueios", "#58a6ff"), ("Ameaças IPS", "#ff7b72")]:
                sub = combined[combined["series"] == series]
                if not sub.empty:
                    fig.add_trace(go.Bar(
                        x            = sub["hora"],
                        y            = sub["count"],
                        name         = series,
                        marker_color = color,
                        opacity      = 0.85,
                    ))
            layout = plotly_dark_layout()
            layout.update({
                "title":   "Eventos de Segurança por Hora",
                "barmode": "group",
                "height":  320,
                "xaxis":   {"title": "Hora", "gridcolor": "#1e3a5f", "zerolinecolor": "#1e3a5f"},
                "yaxis":   {"title": "Eventos", "gridcolor": "#1e3a5f", "zerolinecolor": "#1e3a5f"},
                "legend":  {"orientation": "h", "y": 1.08},
            })
            fig.update_layout(**layout)
            st.plotly_chart(fig, use_container_width=True)

    st.divider()

    # ------------------------------------------------------------------
    # Threat severity distribution
    # ------------------------------------------------------------------
    st.subheader("Distribuição por Severidade")

    if not threat_df.empty:
        sev_counts = threat_df.groupby("severity").size().reset_index(name="count")
        sev_counts["color"] = sev_counts["severity"].map(
            lambda s: _SEVERITY_COLOR.get(s, "#484f58")
        )

        col_sev, col_sev_table = st.columns([1, 1])
        with col_sev:
            fig2 = go.Figure(go.Bar(
                x            = sev_counts["severity"],
                y            = sev_counts["count"],
                marker_color = sev_counts["color"],
                text         = sev_counts["count"],
                textposition = "outside",
                textfont     = {"color": "#e2e8f0"},
                hovertemplate="<b>%{x}</b><br>Ameaças: %{y}<extra></extra>",
            ))
            layout2 = plotly_dark_layout()
            layout2.update({
                "xaxis": {"title": "Severidade", "gridcolor": "#1e3a5f", "zerolinecolor": "#1e3a5f"},
                "yaxis": {"title": "Total de Ameaças", "gridcolor": "#1e3a5f", "zerolinecolor": "#1e3a5f"},
                "showlegend": False,
                "height": 280,
                "margin": {"t": 30, "b": 30, "l": 20, "r": 20},
            })
            fig2.update_layout(**layout2)
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
    # Suspicious devices detail — HTML red cards
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
            ip_str   = row.get("ip") or "IP desconhecido"
            mac_str  = row.get("mac") or "—"
            name_str = row.get("name") or mac_str
            blocks   = row.get("total_blocks") or 0
            reason   = row.get("reason") or "—"
            last_seen = str(row.get("last_seen") or "—")

            card_html = f"""
<div style="background:#1a0d0d; border:1px solid #ff7b72; border-left:4px solid #ff7b72;
     border-radius:12px; padding:16px 20px; margin:6px 0;
     box-shadow:0 4px 12px rgba(255,123,114,0.15);">
  <div style="display:flex; justify-content:space-between; align-items:flex-start;">
    <div>
      <div style="color:#ff7b72; font-size:15px; font-weight:700;">
        🔴 {name_str}
      </div>
      <div style="color:#6b7280; font-size:12px; margin-top:4px;">
        MAC: <code style="color:#94a3b8;">{mac_str}</code>
        &nbsp;|&nbsp; IP: {ip_str}
      </div>
      <div style="color:#94a3b8; font-size:12px; margin-top:6px;">
        <b>Motivo:</b> {reason}
      </div>
      <div style="color:#6b7280; font-size:11px; margin-top:4px;">
        Último visto: {last_seen}
      </div>
    </div>
    <div style="text-align:right; min-width:80px;">
      <div style="color:#ff7b72; font-size:28px; font-weight:800;">{blocks}</div>
      <div style="color:#94a3b8; font-size:11px;">bloqueios</div>
    </div>
  </div>
</div>
"""
            st.markdown(card_html, unsafe_allow_html=True)

    st.divider()

    # ------------------------------------------------------------------
    # Rogue APs section
    # ------------------------------------------------------------------
    st.subheader("APs Vizinhos / Rogues Detectados")

    rogue_df = _load_rogue_aps(db)
    if rogue_df.empty:
        st.success("Nenhum AP rogue/vizinho registrado.")
    else:
        rogue_count = int(rogue_df["is_rogue"].sum()) if "is_rogue" in rogue_df.columns else 0
        neighbor_count = len(rogue_df) - rogue_count

        c1, c2 = st.columns(2)
        with c1:
            st.markdown(
                metric_card("APs Rogues", str(rogue_count), "Marcados como rogue", "⚠️", "#ff7b72"),
                unsafe_allow_html=True,
            )
        with c2:
            st.markdown(
                metric_card("APs Vizinhos", str(neighbor_count), "Redes adjacentes", "📡", "#ffa657"),
                unsafe_allow_html=True,
            )

        display = rogue_df.copy()
        display["Rogue"]    = display["is_rogue"].apply(lambda v: "⚠️ Sim" if v else "Vizinho")
        display["Sinal"]    = display["signal"].apply(lambda s: f"{s} dBm" if s is not None else "—")
        display["1ª Detecção"] = pd.to_datetime(display["first_seen"]).dt.strftime("%d/%m %H:%M")
        display["Última Vez"]  = pd.to_datetime(display["last_seen"]).dt.strftime("%d/%m %H:%M")

        st.dataframe(
            display[[
                "Rogue", "ssid", "bssid", "channel", "Sinal",
                "security", "1ª Detecção", "Última Vez",
            ]].rename(columns={
                "ssid":     "SSID",
                "bssid":    "BSSID",
                "channel":  "Canal",
                "security": "Segurança",
            }),
            use_container_width=True,
            hide_index=True,
        )
