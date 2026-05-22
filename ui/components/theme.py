"""
Dark NOC theme — CSS injection, HTML card helpers, and formatting utilities.

Import and call inject_css() once at the top of each page render function,
or once in app.py before routing.
"""
from __future__ import annotations

import streamlit as st

# ------------------------------------------------------------------
# CSS — dark NOC theme
# ------------------------------------------------------------------

_CSS = """
<style>
/* Dark NOC Theme */
.stApp {
    background: linear-gradient(135deg, #0a0e1a 0%, #0d1117 100%);
}
[data-testid="stSidebar"] {
    background: #0d1117 !important;
    border-right: 1px solid #1e3a5f;
}
h1, h2, h3 {
    color: #e2e8f0 !important;
}
[data-testid="stMetric"] {
    background: #111827;
    border: 1px solid #1e3a5f;
    border-radius: 12px;
    padding: 16px !important;
    box-shadow: 0 4px 6px rgba(0,0,0,0.3);
}
[data-testid="stMetricValue"] {
    color: #58a6ff !important;
}
[data-testid="stMetricLabel"] {
    color: #94a3b8 !important;
}
hr {
    border-color: #1e3a5f !important;
}
.stButton>button {
    background: #1e3a5f;
    color: #58a6ff;
    border: 1px solid #58a6ff;
    border-radius: 8px;
}
.stButton>button:hover {
    background: #58a6ff;
    color: #0d1117;
}
[data-testid="stDataFrame"] {
    border: 1px solid #1e3a5f;
    border-radius: 8px;
}
[data-testid="stSelectbox"] > div > div {
    background: #111827;
    border-color: #1e3a5f;
}
.stAlert {
    border-radius: 8px;
}
.stCaption {
    color: #6b7280 !important;
}
/* Tab styling */
[data-testid="stTabs"] [data-baseweb="tab-list"] {
    background: #111827;
    border-radius: 8px;
    border: 1px solid #1e3a5f;
}
[data-testid="stTabs"] [data-baseweb="tab"] {
    color: #94a3b8;
}
[data-testid="stTabs"] [aria-selected="true"] {
    color: #58a6ff !important;
    border-bottom-color: #58a6ff !important;
}
</style>
"""


def inject_css() -> None:
    """Inject the dark NOC CSS theme into the Streamlit page."""
    st.markdown(_CSS, unsafe_allow_html=True)


# ------------------------------------------------------------------
# HTML card helpers
# ------------------------------------------------------------------

def metric_card(
    title: str,
    value: str,
    subtitle: str = "",
    icon: str = "📊",
    color: str = "#58a6ff",
) -> str:
    """Return an HTML string for a styled NOC metric card."""
    return f"""
<div style="background:#111827; border:1px solid #1e3a5f; border-left:4px solid {color};
     border-radius:12px; padding:20px 24px; margin:4px 0;
     box-shadow:0 4px 12px rgba(0,0,0,0.4);">
  <div style="display:flex; align-items:center; justify-content:space-between;">
    <div>
      <div style="color:#94a3b8; font-size:12px; font-weight:600;
           text-transform:uppercase; letter-spacing:0.08em;">{title}</div>
      <div style="color:{color}; font-size:30px; font-weight:700;
           margin-top:6px; line-height:1;">{value}</div>
      <div style="color:#6b7280; font-size:12px; margin-top:4px;">{subtitle}</div>
    </div>
    <div style="font-size:38px; opacity:0.5;">{icon}</div>
  </div>
</div>
"""


def status_badge(online: bool) -> str:
    """Return an HTML pill badge: green for online, red for offline."""
    if online:
        return (
            '<span style="background:#1a3a2a; color:#3fb950; border:1px solid #3fb950; '
            'border-radius:12px; padding:2px 10px; font-size:12px; font-weight:600;">'
            '● Online</span>'
        )
    return (
        '<span style="background:#3a1a1a; color:#ff7b72; border:1px solid #ff7b72; '
        'border-radius:12px; padding:2px 10px; font-size:12px; font-weight:600;">'
        '● Offline</span>'
    )


def signal_bar(rssi: int | None) -> str:
    """Return an HTML signal strength indicator coloured by RSSI level."""
    if rssi is None:
        return '<span style="color:#484f58;">—</span>'

    if rssi >= -50:
        color, label, bars = "#3fb950", "Excelente", 4
    elif rssi >= -65:
        color, label, bars = "#58a6ff", "Bom", 3
    elif rssi >= -80:
        color, label, bars = "#ffa657", "Regular", 2
    else:
        color, label, bars = "#ff7b72", "Fraco", 1

    filled = "▮" * bars
    empty  = "▯" * (4 - bars)
    return (
        f'<span style="color:{color}; font-size:13px;" title="{rssi} dBm — {label}">'
        f'{filled}<span style="color:#484f58;">{empty}</span>'
        f' <small>{rssi} dBm</small></span>'
    )


# ------------------------------------------------------------------
# Formatting helpers
# ------------------------------------------------------------------

def fmt_bytes(n: int | float | None) -> str:
    """Format a byte count as a human-readable string (B, KB, MB, GB, TB)."""
    if n is None:
        return "—"
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def fmt_bytes_rate(n: int | float | None) -> str:
    """Format a bytes/s rate as a human-readable string."""
    if n is None:
        return "—"
    return f"{fmt_bytes(n)}/s"


def fmt_uptime(seconds: int | None) -> str:
    """Format seconds into 'Xd Xh Xm' string."""
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


# ------------------------------------------------------------------
# Device type mapping
# ------------------------------------------------------------------

DEVICE_ICONS: dict[str, str] = {
    "phone":          "📱",
    "computer":       "💻",
    "tablet":         "📱",
    "gaming":         "🎮",
    "tv":             "📺",
    "iot":            "🏠",
    "printer":        "🖨️",
    "camera":         "📷",
    "infrastructure": "🔧",
    "unknown":        "❓",
}

DEVICE_COLORS: dict[str, str] = {
    "phone":          "#58a6ff",
    "computer":       "#3fb950",
    "tablet":         "#79c0ff",
    "gaming":         "#d2a8ff",
    "tv":             "#ffa657",
    "iot":            "#39d0d8",
    "printer":        "#f0883e",
    "camera":         "#ff7b72",
    "infrastructure": "#6e7681",
    "unknown":        "#484f58",
}


# ------------------------------------------------------------------
# Plotly dark layout defaults
# ------------------------------------------------------------------

def plotly_dark_layout() -> dict:
    """Return a dict of Plotly layout defaults for the dark NOC theme."""
    return {
        "template":       "plotly_dark",
        "paper_bgcolor":  "rgba(0,0,0,0)",
        "plot_bgcolor":   "rgba(13,17,23,1)",
        "font":           {"color": "#94a3b8", "family": "Inter, system-ui, sans-serif"},
        "title_font":     {"color": "#e2e8f0"},
        "legend":         {"bgcolor": "rgba(17,24,39,0.8)", "bordercolor": "#1e3a5f",
                           "borderwidth": 1},
        "xaxis":          {"gridcolor": "#1e3a5f", "zerolinecolor": "#1e3a5f"},
        "yaxis":          {"gridcolor": "#1e3a5f", "zerolinecolor": "#1e3a5f"},
        "margin":         {"t": 50, "b": 30, "l": 20, "r": 20},
    }
