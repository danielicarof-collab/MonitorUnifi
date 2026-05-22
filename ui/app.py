"""
UniFi Intelligence Hub — Streamlit Dashboard

Entry point for the web interface.  Run via:
  streamlit run ui/app.py
  -- or --
  python run.py ui
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

# Allow imports from the project root when run directly via streamlit
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv
load_dotenv(ROOT / ".env")

import streamlit as st

from src.database_manager import DatabaseManager
from ui.components import overview, violators, security, reports, devices, infrastructure
from ui.components.theme import inject_css

# ------------------------------------------------------------------
# Page config (must be first Streamlit call)
# ------------------------------------------------------------------
st.set_page_config(
    page_title="UniFi Intelligence Hub",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ------------------------------------------------------------------
# Database connection (cached across Streamlit reruns)
# ------------------------------------------------------------------
@st.cache_resource
def _get_db() -> DatabaseManager:
    db_url = os.getenv("DB_URL", f"sqlite:///{ROOT}/data/unifi_hub.db")
    db = DatabaseManager(db_url)
    db.initialize_schema()
    return db


# ------------------------------------------------------------------
# Sidebar navigation
# ------------------------------------------------------------------
def _sidebar() -> str:
    with st.sidebar:
        # Styled text logo instead of external image URL (avoids network failures)
        st.markdown(
            """
            <div style="text-align:center; padding: 12px 0 8px;">
              <div style="font-size:28px; font-weight:800; color:#58a6ff;
                          letter-spacing:0.05em;">UniFi</div>
              <div style="font-size:12px; color:#94a3b8; font-weight:600;
                          text-transform:uppercase; letter-spacing:0.12em;">
                Intelligence Hub</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.caption("Monitoramento e Auditoria Avançada")
        st.divider()

        page = st.radio(
            "Navegação",
            options=[
                "🏠 Visão Geral",
                "📡 Dispositivos",
                "🖧 Infraestrutura",
                "🚫 Infratores",
                "🛡️ Segurança",
                "📊 Relatórios",
            ],
            label_visibility="collapsed",
        )

        st.divider()

        # Manual refresh button
        if st.button("🔄 Atualizar Dados", use_container_width=True):
            st.cache_data.clear()
            st.rerun()

        # Collector status hint
        st.caption(
            "**Collector:** Execute `python run.py collect` em outro terminal "
            "para iniciar a coleta de dados em tempo real."
        )

        db_url = os.getenv("DB_URL", "sqlite:///./data/unifi_hub.db")
        st.caption(f"**DB:** `{db_url.split('/')[-1]}`")

    return page


# ------------------------------------------------------------------
# Main
# ------------------------------------------------------------------
def main() -> None:
    inject_css()
    db   = _get_db()
    page = _sidebar()

    if page == "🏠 Visão Geral":
        overview.render(db)
    elif page == "📡 Dispositivos":
        devices.render(db)
    elif page == "🖧 Infraestrutura":
        infrastructure.render(db)
    elif page == "🚫 Infratores":
        violators.render(db)
    elif page == "🛡️ Segurança":
        security.render(db)
    elif page == "📊 Relatórios":
        reports.render(db)


if __name__ == "__main__":
    main()
