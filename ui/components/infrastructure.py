"""
Infrastructure page — AP stats, client distribution, rogue/neighbor APs.
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


@st.cache_data(ttl=60, show_spinner=False)
def _load_rogue_aps(_db: DatabaseManager) -> pd.DataFrame:
    return _db.get_rogue_aps()


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


def _ap_card(row: pd.Series) -> str:
    """Return HTML for a single AP card."""
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
<div style="background:#f8f9fa; border:1px solid #dee2e6; border-left:4px solid {sat_color};
     border-radius:12px; padding:18px 22px; margin:6px 0;
     box-shadow:0 2px 8px rgba(0,0,0,0.08);">
  <div style="display:flex; justify-content:space-between; align-items:flex-start;">
    <div>
      <div style="color:#1a1a2e; font-size:16px; font-weight:700;">{name}</div>
      <div style="color:#6c757d; font-size:12px; margin-top:2px;">
        {model} &nbsp;|&nbsp; {ip}
      </div>
    </div>
    <div style="text-align:right;">
      <div style="color:{sat_color}; font-size:18px; font-weight:700;">{sat_label}</div>
      <div style="color:#888; font-size:11px;">satisfação</div>
    </div>
  </div>
  <div style="margin-top:12px; display:grid; grid-template-columns:1fr 1fr; gap:8px;">
    <div style="background:#ffffff; border:1px solid #e9ecef; border-radius:8px; padding:8px 12px;">
      <div style="color:#888; font-size:11px; text-transform:uppercase;">Clientes</div>
      <div style="color:#1976d2; font-size:20px; font-weight:700;">{clients_total}</div>
      <div style="color:#6c757d; font-size:11px;">
        2.4G: {clients_24g} &nbsp;|&nbsp; 5G: {clients_5g}
        {f" &nbsp;|&nbsp; 6G: {clients_6g}" if clients_6g else ""}
      </div>
    </div>
    <div style="background:#ffffff; border:1px solid #e9ecef; border-radius:8px; padding:8px 12px;">
      <div style="color:#888; font-size:11px; text-transform:uppercase;">Throughput</div>
      <div style="color:#2e7d32; font-size:13px; font-weight:600;">↓ {rx_rate}</div>
      <div style="color:#e65100; font-size:13px; font-weight:600;">↑ {tx_rate}</div>
    </div>
  </div>
  <div style="margin-top:8px; color:#6c757d; font-size:11px;">
    ⏱ Uptime: {uptime}
    {f' &nbsp;|&nbsp; 📻 Canais:{ch_str}' if ch_str else ''}
  </div>
</div>
"""


# ------------------------------------------------------------------
# AP cards section
# ------------------------------------------------------------------

def _render_ap_cards(ap_df: pd.DataFrame) -> None:
    st.subheader("Dispositivos de Rede (APs / Switches / Gateways)")

    if ap_df.empty:
        st.warning(
            "**Nenhuma estatística de AP disponível.**\n\n"
            "Possíveis causas:\n"
            "- O collector ainda não rodou — execute `python run.py collect-once`\n"
            "- O usuário UniFi não tem permissão para `/stat/device` "
            "(use role **Administrator** ou **Read-Only Administrator**)\n"
            "- Verifique os logs: `journalctl -u unifi-collector -n 30`"
        )
        return

    # Two-column card layout
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
        x            = df["AP"],
        y            = df["num_clients_24g"].fillna(0),
        name         = "2.4 GHz",
        marker_color = "#ffa657",
    ))
    fig.add_trace(go.Bar(
        x            = df["AP"],
        y            = df["num_clients_5g"].fillna(0),
        name         = "5 GHz",
        marker_color = "#58a6ff",
    ))
    if df["num_clients_6g"].sum() > 0:
        fig.add_trace(go.Bar(
            x            = df["AP"],
            y            = df["num_clients_6g"].fillna(0),
            name         = "6 GHz",
            marker_color = "#d2a8ff",
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
# Main render
# ------------------------------------------------------------------

def render(db: DatabaseManager) -> None:
    st.header("Infraestrutura de Rede")

    ap_df    = _load_ap_stats(db)
    rogue_df = _load_rogue_aps(db)

    # Quick summary metrics
    total_aps     = len(ap_df)
    total_clients = int(ap_df["num_clients"].sum()) if not ap_df.empty else 0
    avg_sat       = int(ap_df["satisfaction"].mean()) if not ap_df.empty and ap_df["satisfaction"].notna().any() else None

    c1, c2, c3 = st.columns(3)
    with c1:
        st.markdown(
            metric_card("APs Gerenciados", str(total_aps), "Dispositivos UniFi",
                        "🔧", "#58a6ff"),
            unsafe_allow_html=True,
        )
    with c2:
        st.markdown(
            metric_card("Clientes Conectados", str(total_clients), "Total atual",
                        "👥", "#3fb950"),
            unsafe_allow_html=True,
        )
    with c3:
        sat_str = f"{avg_sat}%" if avg_sat is not None else "—"
        sat_color = "#3fb950" if avg_sat and avg_sat >= 80 else "#ffa657" if avg_sat and avg_sat >= 60 else "#ff7b72"
        st.markdown(
            metric_card("Satisfação Média", sat_str, "Score UniFi (0–100)",
                        "📊", sat_color),
            unsafe_allow_html=True,
        )

    st.divider()

    _render_ap_cards(ap_df)

    if not ap_df.empty:
        st.divider()
        _render_client_distribution(ap_df)

    st.divider()
    _render_rogue_aps(rogue_df)
