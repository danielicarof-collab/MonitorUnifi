"""
Painel do Infrator — ranking de dispositivos que mais disparam bloqueios.
"""
from __future__ import annotations

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from src.database_manager import DatabaseManager
from ui.components.theme import metric_card, plotly_dark_layout

_RULE_TYPE_LABELS = {
    "traffic_rule":  "🟠 Regra de Tráfego (App/DPI)",
    "firewall_rule": "🔵 Regra de Firewall (IP/Porta)",
}


@st.cache_data(ttl=60, show_spinner=False)
def _load_violators(_db: DatabaseManager, days: int, limit: int) -> pd.DataFrame:
    return _db.get_top_violators(days=days, limit=limit)


@st.cache_data(ttl=60, show_spinner=False)
def _load_recent(_db: DatabaseManager) -> pd.DataFrame:
    return _db.get_recent_blocks(limit=500)


@st.cache_data(ttl=60, show_spinner=False)
def _load_by_category(_db: DatabaseManager, days: int) -> pd.DataFrame:
    return _db.get_blocks_by_category(days=days)


def render(db: DatabaseManager) -> None:
    st.header("Painel do Infrator")
    st.caption("Dispositivos que mais tentaram burlar as regras de bloqueio.")

    # ------------------------------------------------------------------
    # Filters
    # ------------------------------------------------------------------
    col_days, col_limit, _ = st.columns([1, 1, 2])
    days  = col_days.selectbox("Período", [7, 14, 30, 90], index=2,
                               format_func=lambda x: f"{x} dias")
    limit = col_limit.selectbox("Top N", [5, 10, 20], index=1)

    # ------------------------------------------------------------------
    # Ranking bar chart
    # ------------------------------------------------------------------
    df = _load_violators(db, days, limit)

    if df.empty:
        st.info("Nenhum bloqueio registrado no período selecionado.")
        return

    df["label"] = df.apply(
        lambda r: r["name"] or r["mac"] or "Desconhecido", axis=1
    )
    df_sorted = df.sort_values("total_blocks", ascending=True)

    # Dark theme bar chart
    fig = go.Figure(go.Bar(
        x            = df_sorted["total_blocks"],
        y            = df_sorted["label"],
        orientation  = "h",
        marker=dict(
            color     = df_sorted["total_blocks"],
            colorscale= [[0.0, "#582020"], [0.5, "#c0392b"], [1.0, "#ff4d4d"]],
            showscale = False,
        ),
        text         = df_sorted["total_blocks"],
        textposition = "outside",
        textfont     = {"color": "#e2e8f0"},
        hovertemplate="<b>%{y}</b><br>Bloqueios: %{x}<extra></extra>",
    ))

    layout = plotly_dark_layout()
    layout.update({
        "title":  f"Top {limit} Infratores — últimos {days} dias",
        "height": max(300, len(df_sorted) * 40 + 100),
        "xaxis":  {"title": "Bloqueios", "gridcolor": "#1e3a5f", "zerolinecolor": "#1e3a5f"},
        "yaxis":  {"gridcolor": "rgba(0,0,0,0)", "zerolinecolor": "#1e3a5f"},
        "margin": {"l": 10, "r": 60, "t": 50, "b": 20},
    })
    fig.update_layout(**layout)
    st.plotly_chart(fig, use_container_width=True)

    # ------------------------------------------------------------------
    # Ranking detail table with column config
    # ------------------------------------------------------------------
    st.subheader("Detalhes do Ranking")

    display_df = df[["label", "mac", "ip", "total_blocks", "last_seen"]].rename(columns={
        "label":        "Dispositivo",
        "mac":          "MAC",
        "ip":           "Último IP",
        "total_blocks": "Bloqueios",
        "last_seen":    "Último Bloqueio",
    }).sort_values("Bloqueios", ascending=False)

    max_blocks = int(display_df["Bloqueios"].max()) if not display_df.empty else 1

    st.dataframe(
        display_df,
        use_container_width=True,
        hide_index=True,
        column_config={
            "Bloqueios": st.column_config.ProgressColumn(
                "Bloqueios",
                min_value=0,
                max_value=max_blocks,
                format="%d",
            ),
        },
    )

    st.divider()

    # ------------------------------------------------------------------
    # Category breakdown pie chart
    # ------------------------------------------------------------------
    cat_df = _load_by_category(db, days)

    if not cat_df.empty:
        st.subheader("Bloqueios por Categoria de Conteúdo")
        col_pie, col_cat_table = st.columns([1, 1])

        with col_pie:
            fig2 = go.Figure(go.Pie(
                labels       = cat_df["category"],
                values       = cat_df["count"],
                hole         = 0.45,
                textinfo     = "percent+label",
                textposition = "inside",
                insidetextorientation="radial",
                marker=dict(
                    colors = px.colors.qualitative.Dark24[:len(cat_df)],
                    line   = dict(color="#0d1117", width=2),
                ),
                hovertemplate="<b>%{label}</b><br>%{value} bloqueios<br>%{percent}<extra></extra>",
            ))
            layout2 = plotly_dark_layout()
            layout2.update({
                "showlegend": False,
                "height":     340,
                "margin":     {"t": 10, "b": 10, "l": 10, "r": 10},
            })
            fig2.update_layout(**layout2)
            st.plotly_chart(fig2, use_container_width=True)

        with col_cat_table:
            st.dataframe(
                cat_df.rename(columns={"category": "Categoria", "count": "Bloqueios"}),
                use_container_width=True,
                hide_index=True,
                column_config={
                    "Bloqueios": st.column_config.NumberColumn("Bloqueios", format="%d"),
                },
            )

    st.divider()

    # ------------------------------------------------------------------
    # Recent blocks feed
    # ------------------------------------------------------------------
    st.subheader("Feed de Bloqueios Recentes")

    recent_df = _load_recent(db)
    if recent_df.empty:
        st.info("Nenhum bloqueio recente encontrado.")
        return

    recent_df["rule_type"] = recent_df["rule_type"].map(
        lambda x: _RULE_TYPE_LABELS.get(x, x)
    )

    # Optional MAC filter
    all_macs = ["Todos"] + sorted(recent_df["client_mac"].dropna().unique().tolist())
    selected_mac = st.selectbox("Filtrar por MAC", all_macs)
    if selected_mac != "Todos":
        recent_df = recent_df[recent_df["client_mac"] == selected_mac]

    st.dataframe(
        recent_df[[
            "timestamp", "client_name", "client_ip",
            "rule_type", "category", "destination",
        ]].rename(columns={
            "timestamp":   "Hora",
            "client_name": "Dispositivo",
            "client_ip":   "IP Origem",
            "rule_type":   "Tipo de Regra",
            "category":    "Categoria",
            "destination": "Destino",
        }),
        use_container_width=True,
        hide_index=True,
    )
