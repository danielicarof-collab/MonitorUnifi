"""
Relatórios Gerenciais — exportação PDF e CSV.

O PDF inclui:
  - Capa com período e data de geração
  - Resumo executivo (KPIs)
  - Tabela de uptime WAN mensal
  - Top 10 Infratores
  - Top 10 Incidentes de Segurança
"""
from __future__ import annotations

import io
from datetime import datetime
from typing import Any, Dict

import matplotlib
matplotlib.use("Agg")  # non-interactive backend for server rendering
import matplotlib.pyplot as plt
import pandas as pd
import streamlit as st
from fpdf import FPDF

from src.database_manager import DatabaseManager


# ------------------------------------------------------------------
# PDF builder
# ------------------------------------------------------------------

class _ReportPDF(FPDF):
    """Custom FPDF subclass with header/footer and helper methods."""

    BRAND_COLOR   = (0,  82, 147)    # Ubiquiti-ish navy blue
    ACCENT_COLOR  = (0, 194, 120)    # green
    WARN_COLOR    = (220,  53,  69)  # red

    def __init__(self, title: str, period: str) -> None:
        super().__init__()
        self._title  = title
        self._period = period
        self.set_auto_page_break(auto=True, margin=15)

    def header(self) -> None:
        if self.page_no() == 1:
            return
        self.set_fill_color(*self.BRAND_COLOR)
        self.rect(0, 0, 210, 12, "F")
        self.set_text_color(255, 255, 255)
        self.set_font("Helvetica", "B", 9)
        self.set_xy(10, 3)
        self.cell(0, 6, f"UniFi Intelligence Hub  |  {self._period}", align="L")
        self.set_xy(-50, 3)
        self.cell(40, 6, f"Pág. {self.page_no()}", align="R")
        self.set_text_color(0, 0, 0)
        self.ln(12)

    def footer(self) -> None:
        if self.page_no() == 1:
            return
        self.set_y(-12)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(150, 150, 150)
        self.cell(0, 8, f"Gerado em {datetime.utcnow().strftime('%d/%m/%Y %H:%M')} UTC", align="C")

    # ------------------------------------------------------------------
    # Cover page
    # ------------------------------------------------------------------

    def cover(self) -> None:
        self.add_page()
        # Background band
        self.set_fill_color(*self.BRAND_COLOR)
        self.rect(0, 0, 210, 80, "F")

        self.set_text_color(255, 255, 255)
        self.set_font("Helvetica", "B", 28)
        self.set_xy(0, 20)
        self.cell(210, 14, "UniFi Intelligence Hub", align="C")

        self.set_font("Helvetica", "", 16)
        self.set_xy(0, 38)
        self.cell(210, 10, "Relatório Gerencial de Rede", align="C")

        self.set_font("Helvetica", "B", 18)
        self.set_xy(0, 56)
        self.cell(210, 10, self._period, align="C")

        self.set_text_color(0, 0, 0)
        self.set_xy(0, 90)
        self.set_font("Helvetica", "", 11)
        self.multi_cell(
            210, 7,
            "Este relatório foi gerado automaticamente pelo UniFi Intelligence Hub.\n"
            "Ele consolida dados históricos coletados via API do UDM-Pro e apresenta\n"
            "métricas de disponibilidade, segurança e comportamento de usuários.",
            align="C",
        )

    # ------------------------------------------------------------------
    # Section heading
    # ------------------------------------------------------------------

    def section_title(self, text: str) -> None:
        self.set_fill_color(*self.BRAND_COLOR)
        self.set_text_color(255, 255, 255)
        self.set_font("Helvetica", "B", 12)
        self.cell(0, 9, f"  {text}", fill=True, ln=True)
        self.set_text_color(0, 0, 0)
        self.ln(3)

    # ------------------------------------------------------------------
    # KPI row
    # ------------------------------------------------------------------

    def kpi_row(self, items: list[tuple[str, str]]) -> None:
        col_w = 190 // len(items)
        for label, value in items:
            self.set_fill_color(240, 245, 255)
            self.set_font("Helvetica", "B", 16)
            self.cell(col_w, 14, value, border=1, align="C", fill=True)
        self.ln()
        for label, _ in items:
            self.set_font("Helvetica", "", 8)
            self.cell(col_w, 6, label, align="C")
        self.ln(10)

    # ------------------------------------------------------------------
    # Generic data table
    # ------------------------------------------------------------------

    def data_table(
        self,
        df: pd.DataFrame,
        col_widths: list[int] | None = None,
        max_rows: int = 30,
    ) -> None:
        if df.empty:
            self.set_font("Helvetica", "I", 10)
            self.cell(0, 8, "Nenhum dado disponível.", ln=True)
            return

        cols = list(df.columns)
        widths = col_widths or [190 // len(cols)] * len(cols)

        # Header row
        self.set_fill_color(*self.BRAND_COLOR)
        self.set_text_color(255, 255, 255)
        self.set_font("Helvetica", "B", 8)
        for col, w in zip(cols, widths):
            self.cell(w, 7, str(col)[:22], border=1, align="C", fill=True)
        self.ln()

        # Data rows (alternating background)
        self.set_text_color(0, 0, 0)
        self.set_font("Helvetica", "", 8)
        for i, (_, row) in enumerate(df.head(max_rows).iterrows()):
            fill = i % 2 == 0
            if fill:
                self.set_fill_color(245, 248, 255)
            for val, w in zip(row, widths):
                cell_val = str(val) if pd.notna(val) else "—"
                self.cell(w, 6, cell_val[:25], border=1, fill=fill)
            self.ln()
        self.ln(4)

    # ------------------------------------------------------------------
    # Embedded matplotlib chart
    # ------------------------------------------------------------------

    def embed_chart(self, fig: Any, width_mm: int = 180) -> None:
        buf = io.BytesIO()
        fig.savefig(buf, format="png", dpi=150, bbox_inches="tight")
        buf.seek(0)
        plt.close(fig)
        x = (210 - width_mm) / 2
        self.image(buf, x=x, w=width_mm)
        self.ln(4)


# ------------------------------------------------------------------
# Public generator function
# ------------------------------------------------------------------

def generate_pdf(
    db: DatabaseManager,
    year: int,
    month: int,
) -> bytes:
    import calendar
    period = f"{calendar.month_name[month]} {year}"
    pdf = _ReportPDF(title="Relatório Gerencial", period=period)

    # Cover
    pdf.cover()

    # -- Page 2: Executive Summary --
    pdf.add_page()
    pdf.section_title("1. Resumo Executivo")

    stats = db.get_summary_stats(days=30)
    wan   = db.get_wan_uptime_stats(year, month)

    uptime_str = f"{wan['uptime_pct']}%" if wan["uptime_pct"] is not None else "N/D"
    pdf.kpi_row([
        ("Disponibilidade WAN",        uptime_str),
        ("Bloqueios (30 dias)",        str(stats["total_blocks"])),
        ("Ameaças IPS/IDS (30 dias)",  str(stats["total_threats"])),
        ("Dispositivos Suspeitos",     str(stats["suspicious_devices"])),
    ])

    pdf.set_font("Helvetica", "", 10)
    pdf.multi_cell(
        0, 6,
        f"Durante o mês de {period}, a rede registrou {stats['total_blocks']} tentativas de acesso "
        f"bloqueadas oriundas de {stats['unique_violators']} dispositivos distintos. "
        f"O sistema de detecção de ameaças (IPS/IDS) registrou {stats['total_threats']} eventos. "
        f"A disponibilidade do link WAN principal foi de {uptime_str}.",
        ln=True,
    )
    pdf.ln(4)

    # -- WAN Uptime section --
    pdf.section_title("2. Disponibilidade WAN — Mês de Referência")

    uptime_table = pd.DataFrame([{
        "Mês":                    period,
        "Amostras Totais":        wan["total_samples"],
        "Amostras Online":        wan["up_samples"],
        "Disponibilidade (%)":    wan["uptime_pct"] or "N/D",
        "Latência Média (ms)":    wan["avg_latency_ms"] or "N/D",
    }])
    pdf.data_table(uptime_table, col_widths=[38, 35, 35, 42, 40])

    # Uptime gauge chart
    if wan["uptime_pct"] is not None:
        fig_g, ax = plt.subplots(figsize=(4, 2.5))
        ax.barh(["Uptime"], [wan["uptime_pct"]], color="#00cc66")
        ax.barh(["Uptime"], [100 - wan["uptime_pct"]], left=[wan["uptime_pct"]], color="#ffe0e0")
        ax.set_xlim(0, 100)
        ax.set_xlabel("Disponibilidade (%)")
        ax.set_title(f"Uptime WAN — {period}")
        for spine in ax.spines.values():
            spine.set_visible(False)
        pdf.embed_chart(fig_g, width_mm=130)

    # -- Top 10 Violators --
    pdf.add_page()
    pdf.section_title("3. Top 10 Infratores (Últimos 30 dias)")

    viol_df = db.get_top_violators(days=30, limit=10)
    if not viol_df.empty:
        display = viol_df[["name", "mac", "ip", "total_blocks", "last_seen"]].copy()
        display["name"] = display.apply(
            lambda r: r["name"] or r["mac"] or "Desconhecido", axis=1
        )
        display = display.rename(columns={
            "name":         "Dispositivo",
            "mac":          "MAC",
            "ip":           "Último IP",
            "total_blocks": "Bloqueios",
            "last_seen":    "Último Bloqueio",
        })
        pdf.data_table(display, col_widths=[50, 42, 30, 22, 46])

        # Bar chart
        fig_v, ax2 = plt.subplots(figsize=(7, max(3, len(display) * 0.4 + 1)))
        colors = ["#c0392b" if b >= display["Bloqueios"].max() * 0.8 else "#e67e22"
                  for b in display["Bloqueios"]]
        ax2.barh(display["Dispositivo"], display["Bloqueios"], color=colors)
        ax2.set_xlabel("Número de Bloqueios")
        ax2.set_title("Top 10 Infratores")
        ax2.invert_yaxis()
        for spine in ax2.spines.values():
            spine.set_visible(False)
        pdf.embed_chart(fig_v, width_mm=160)

    # -- Top 10 Threats --
    pdf.add_page()
    pdf.section_title("4. Top 10 Incidentes de Segurança (Últimos 30 dias)")

    threat_df = db.get_top_threats(days=30, limit=10)
    if not threat_df.empty:
        display_t = threat_df[["timestamp", "client_name", "threat_type", "severity", "action"]].copy()
        display_t["timestamp"] = pd.to_datetime(display_t["timestamp"]).dt.strftime("%d/%m %H:%M")
        display_t = display_t.rename(columns={
            "timestamp":   "Hora",
            "client_name": "Origem",
            "threat_type": "Tipo",
            "severity":    "Severidade",
            "action":      "Ação",
        })
        pdf.data_table(display_t, col_widths=[28, 45, 50, 28, 39])

    pdf.set_font("Helvetica", "I", 9)
    pdf.set_text_color(100, 100, 100)
    pdf.cell(
        0, 8,
        f"Relatório gerado em {datetime.utcnow().strftime('%d/%m/%Y %H:%M')} UTC "
        "pelo UniFi Intelligence Hub.",
        ln=True, align="C",
    )

    return bytes(pdf.output())


# ------------------------------------------------------------------
# Streamlit page
# ------------------------------------------------------------------

def render(db: DatabaseManager) -> None:
    st.header("Relatórios Gerenciais")
    st.caption("Gere relatórios PDF ou exporte dados brutos em CSV.")

    now = datetime.utcnow()
    col_y, col_m, col_gen = st.columns([1, 1, 2])

    year  = col_y.number_input("Ano",  min_value=2020, max_value=now.year, value=now.year)
    month = col_m.number_input("Mês",  min_value=1,    max_value=12,       value=now.month)

    st.divider()

    # ------------------------------------------------------------------
    # PDF export
    # ------------------------------------------------------------------
    st.subheader("Relatório PDF Gerencial")
    st.markdown(
        "Inclui uptime WAN, Top 10 infratores, Top 10 incidentes de segurança "
        "e resumo executivo em formato profissional."
    )

    if st.button("Gerar PDF", type="primary"):
        with st.spinner("Gerando relatório PDF…"):
            try:
                pdf_bytes = generate_pdf(db, int(year), int(month))
                import calendar
                filename = f"unifi_report_{year}_{month:02d}.pdf"
                st.download_button(
                    label=f"📥 Baixar {filename}",
                    data=pdf_bytes,
                    file_name=filename,
                    mime="application/pdf",
                )
                st.success("PDF gerado com sucesso!")
            except Exception as exc:
                st.error(f"Erro ao gerar PDF: {exc}")

    st.divider()

    # ------------------------------------------------------------------
    # CSV exports
    # ------------------------------------------------------------------
    st.subheader("Exportar Dados em CSV")

    col_a, col_b = st.columns(2)

    with col_a:
        st.markdown("**Histórico de Bloqueios**")
        if st.button("Exportar Bloqueios (CSV)"):
            df = db.get_recent_blocks(limit=10_000)
            if df.empty:
                st.warning("Nenhum dado encontrado.")
            else:
                st.download_button(
                    "📥 Baixar bloqueios.csv",
                    data=df.to_csv(index=False).encode("utf-8"),
                    file_name=f"bloqueios_{now.strftime('%Y%m%d')}.csv",
                    mime="text/csv",
                )

    with col_b:
        st.markdown("**Eventos de Ameaça**")
        if st.button("Exportar Ameaças (CSV)"):
            df = db.get_top_threats(days=365, limit=10_000)
            if df.empty:
                st.warning("Nenhum dado encontrado.")
            else:
                st.download_button(
                    "📥 Baixar ameacas.csv",
                    data=df.to_csv(index=False).encode("utf-8"),
                    file_name=f"ameacas_{now.strftime('%Y%m%d')}.csv",
                    mime="text/csv",
                )

    st.divider()

    st.subheader("Exportar Ranking de Infratores")
    period_days = st.slider("Período (dias)", 7, 365, 30)
    if st.button("Exportar Infratores (CSV)"):
        df = db.get_top_violators(days=period_days, limit=500)
        if df.empty:
            st.warning("Nenhum dado encontrado.")
        else:
            st.download_button(
                "📥 Baixar infratores.csv",
                data=df.to_csv(index=False).encode("utf-8"),
                file_name=f"infratores_{now.strftime('%Y%m%d')}.csv",
                mime="text/csv",
            )
