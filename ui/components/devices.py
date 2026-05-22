"""
Devices page — inventory of online and known devices, classified by type.
"""
from __future__ import annotations

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from src.database_manager import DatabaseManager
from ui.components.theme import (
    DEVICE_COLORS, DEVICE_ICONS,
    fmt_bytes_rate, fmt_uptime, signal_bar,
    metric_card, plotly_dark_layout, fmt_datetime_local,
)


# ------------------------------------------------------------------
# Cached data loaders
# ------------------------------------------------------------------

@st.cache_data(ttl=60, show_spinner=False)
def _load_online(_db: DatabaseManager) -> pd.DataFrame:
    return _db.get_latest_client_snapshots()


@st.cache_data(ttl=60, show_spinner=False)
def _load_all(_db: DatabaseManager) -> pd.DataFrame:
    return _db.get_all_clients()


@st.cache_data(ttl=60, show_spinner=False)
def _load_type_counts(_db: DatabaseManager) -> pd.DataFrame:
    return _db.get_device_type_counts()


# ------------------------------------------------------------------
# Tab 1 — Online Now
# ------------------------------------------------------------------

def _render_online_tab(snap_df: pd.DataFrame) -> None:
    if snap_df.empty:
        st.info(
            "Nenhum snapshot de cliente disponível.  "
            "Execute `python run.py collect-once` para iniciar a coleta."
        )
        return

    st.caption(f"**{len(snap_df)}** dispositivos com snapshot recente.")

    df = snap_df.copy()

    # Computed display columns
    df["Tipo"] = df["device_type"].apply(
        lambda t: f"{DEVICE_ICONS.get(t or 'unknown', '❓')} {(t or 'unknown').capitalize()}"
    )
    df["Nome"] = df["name"].fillna(df["mac"])
    df["IP"]   = df["ip"].fillna("—")
    df["Sinal / Banda"] = df.apply(
        lambda r: "Cabeado" if r.get("is_wired") else (r.get("radio_band") or "Wi-Fi"),
        axis=1,
    )
    df["Sinal (dBm)"] = df["signal"].apply(
        lambda s: f"{s} dBm" if s is not None else "Wired"
    )
    df["Download"] = df["rx_bytes_rate"].apply(fmt_bytes_rate)
    df["Upload"]   = df["tx_bytes_rate"].apply(fmt_bytes_rate)
    df["Uptime"]   = df["uptime_sec"].apply(fmt_uptime)
    df["SSID"]     = df["essid"].fillna("—")
    df["AP"]       = df["ap_mac"].fillna("—")
    df["Satisfação"] = df["satisfaction"].apply(
        lambda v: f"{v}%" if v is not None else "—"
    )

    display_cols = [
        "Tipo", "Nome", "IP", "Sinal / Banda", "Sinal (dBm)",
        "Download", "Upload", "Satisfação", "SSID", "Uptime",
    ]

    # Colour-code table via column_config
    st.dataframe(
        df[display_cols],
        use_container_width=True,
        hide_index=True,
        column_config={
            "Satisfação": st.column_config.TextColumn("Satisfação", width="small"),
            "Sinal (dBm)": st.column_config.TextColumn("Sinal", width="small"),
        },
    )

    # Optional: quick signal quality breakdown
    if not df.empty and "signal" in df.columns:
        wired_count = df["is_wired"].sum() if "is_wired" in df.columns else 0
        wireless = df[~df["is_wired"].astype(bool)] if "is_wired" in df.columns else df
        if not wireless.empty and wireless["signal"].notna().any():
            sig = wireless["signal"].dropna()
            excellent = (sig >= -50).sum()
            good      = ((sig >= -65) & (sig < -50)).sum()
            fair      = ((sig >= -80) & (sig < -65)).sum()
            weak      = (sig < -80).sum()

            st.caption(
                f"Sinal Wi-Fi: "
                f"🟢 Excelente: **{excellent}** | "
                f"🔵 Bom: **{good}** | "
                f"🟡 Regular: **{fair}** | "
                f"🔴 Fraco: **{weak}** | "
                f"🔌 Cabeado: **{int(wired_count)}**"
            )


# ------------------------------------------------------------------
# Tab 2 — All Devices
# ------------------------------------------------------------------

def _render_all_tab(all_df: pd.DataFrame) -> None:
    if all_df.empty:
        st.info("Nenhum dispositivo cadastrado ainda.")
        return

    df = all_df.copy()
    df["Tipo"] = df["device_type"].apply(
        lambda t: f"{DEVICE_ICONS.get(t or 'unknown', '❓')} {(t or 'unknown').capitalize()}"
    )
    df["Nome"]       = df["name"].fillna(df["mac"])
    df["IP"]         = df["ip"].fillna("—")
    df["Vendor"]     = df["vendor"].fillna("—")
    df["OS"]         = df["os_name"].fillna("—")
    df["Família"]    = df["dev_family"].fillna("—")
    df["Bloqueios"]  = df["total_blocks"].fillna(0).astype(int)
    df["Suspeito"]   = df["is_suspicious"].apply(lambda v: "⚠️ Sim" if v else "—")
    df["Último Acesso"] = pd.to_datetime(df["last_seen"]).apply(
        lambda dt: fmt_datetime_local(dt.to_pydatetime()) if pd.notna(dt) else "—"
    )

    # Search/filter
    search = st.text_input("Buscar dispositivo (nome, MAC, IP, vendor)", "")
    if search:
        mask = (
            df["Nome"].str.contains(search, case=False, na=False) |
            df["mac"].str.contains(search, case=False, na=False) |
            df["IP"].str.contains(search, case=False, na=False) |
            df["Vendor"].str.contains(search, case=False, na=False)
        )
        df = df[mask]

    st.caption(f"**{len(df)}** dispositivos exibidos.")

    display_cols = [
        "Tipo", "Nome", "mac", "IP", "Vendor", "OS",
        "Bloqueios", "Suspeito", "Último Acesso",
    ]

    st.dataframe(
        df[display_cols].rename(columns={"mac": "MAC"}),
        use_container_width=True,
        hide_index=True,
        column_config={
            "Bloqueios": st.column_config.NumberColumn("Bloqueios", format="%d"),
        },
    )


# ------------------------------------------------------------------
# Tab 3 — Classification
# ------------------------------------------------------------------

def _render_classification_tab(type_df: pd.DataFrame, all_df: pd.DataFrame) -> None:
    if type_df.empty:
        st.info("Sem dados de classificação de dispositivos.")
        return

    df = type_df.copy()
    df["device_type"] = df["device_type"].fillna("unknown")

    labels  = df["device_type"].tolist()
    values  = df["count"].tolist()
    colors  = [DEVICE_COLORS.get(lbl, "#484f58") for lbl in labels]
    icons   = [DEVICE_ICONS.get(lbl, "❓") for lbl in labels]
    disp    = [f"{icons[i]} {lbl.capitalize()}" for i, lbl in enumerate(labels)]

    col_chart, col_table = st.columns([1, 1])

    with col_chart:
        fig = go.Figure(go.Pie(
            labels        = disp,
            values        = values,
            hole          = 0.5,
            marker_colors = colors,
            textinfo      = "percent+label",
            textposition  = "inside",
            insidetextorientation="radial",
            hovertemplate="<b>%{label}</b><br>Dispositivos: %{value}<br>%{percent}<extra></extra>",
        ))
        layout = plotly_dark_layout()
        layout.update({
            "title":      "Distribuição por Tipo",
            "showlegend": False,
            "height":     360,
            "margin":     {"t": 50, "b": 10, "l": 10, "r": 10},
        })
        fig.update_layout(**layout)
        st.plotly_chart(fig, use_container_width=True)

    with col_table:
        total = df["count"].sum()
        display = df.rename(columns={"device_type": "Tipo", "count": "Dispositivos"}).copy()
        display["Tipo"] = [f"{icons[i]} {lbl.capitalize()}" for i, lbl in enumerate(labels)]
        display["% do Total"] = (display["Dispositivos"] / total * 100).round(1).astype(str) + "%"
        st.dataframe(display, use_container_width=True, hide_index=True)

    # Classification coverage
    if not all_df.empty:
        unknown_count = len(all_df[all_df["device_type"].isin(["unknown", None, ""])])
        known_count   = len(all_df) - unknown_count
        pct_known     = known_count / len(all_df) * 100 if len(all_df) > 0 else 0
        st.divider()
        st.metric(
            "Cobertura de Classificação",
            f"{pct_known:.1f}%",
            help=f"{known_count} de {len(all_df)} dispositivos classificados",
        )


# ------------------------------------------------------------------
# Main render
# ------------------------------------------------------------------

def render(db: DatabaseManager) -> None:
    st.header("Inventário de Dispositivos")

    snap_df  = _load_online(db)
    all_df   = _load_all(db)
    type_df  = _load_type_counts(db)

    # Quick KPI row
    c1, c2, c3 = st.columns(3)
    with c1:
        st.markdown(
            metric_card("Online Agora", str(len(snap_df)), "Últimos snapshots",
                        "📡", "#3fb950"),
            unsafe_allow_html=True,
        )
    with c2:
        st.markdown(
            metric_card("Dispositivos Conhecidos", str(len(all_df)), "Total cadastrado",
                        "💾", "#58a6ff"),
            unsafe_allow_html=True,
        )
    with c3:
        n_types = len(type_df[type_df["device_type"].notna() & (type_df["device_type"] != "unknown")]) if not type_df.empty else 0
        st.markdown(
            metric_card("Tipos Distintos", str(n_types), "Categorias detectadas",
                        "🗂️", "#d2a8ff"),
            unsafe_allow_html=True,
        )

    st.divider()

    tab1, tab2, tab3 = st.tabs(["📡 Online Agora", "📋 Todos os Dispositivos", "🗂️ Classificação"])

    with tab1:
        _render_online_tab(snap_df)

    with tab2:
        _render_all_tab(all_df)

    with tab3:
        _render_classification_tab(type_df, all_df)
