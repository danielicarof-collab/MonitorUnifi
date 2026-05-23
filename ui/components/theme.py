"""
Dark NOC theme — CSS injection, HTML card helpers, and formatting utilities.

Import and call inject_css() once at the top of each page render function,
or once in app.py before routing.
"""
from __future__ import annotations

import math

import streamlit as st

# ------------------------------------------------------------------
# CSS — dark NOC theme
# ------------------------------------------------------------------

_CSS = """
<style>
/* Subtle improvements only — no background override */
[data-testid="stMetric"] {
    border-left: 3px solid #1976d2;
    border-radius: 8px;
    padding: 8px 12px !important;
}
.stAlert { border-radius: 8px; }
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
    color: str = "#1976d2",
) -> str:
    """Return an HTML string for a styled metric card (theme-neutral)."""
    return f"""
<div style="border:1px solid #e0e0e0; border-left:4px solid {color};
     border-radius:10px; padding:16px 20px; margin:4px 0;
     box-shadow:0 2px 6px rgba(0,0,0,0.08);">
  <div style="display:flex; align-items:center; justify-content:space-between;">
    <div>
      <div style="color:#666; font-size:11px; font-weight:600;
           text-transform:uppercase; letter-spacing:0.08em;">{title}</div>
      <div style="color:{color}; font-size:28px; font-weight:700;
           margin-top:4px; line-height:1;">{value}</div>
      <div style="color:#888; font-size:11px; margin-top:4px;">{subtitle}</div>
    </div>
    <div style="font-size:34px; opacity:0.4;">{icon}</div>
  </div>
</div>
"""


def status_badge(online: bool) -> str:
    """Return an HTML pill badge: green for online, red for offline."""
    if online:
        return (
            '<span style="background:#e8f5e9; color:#2e7d32; border:1px solid #66bb6a; '
            'border-radius:12px; padding:3px 12px; font-size:12px; font-weight:600;">'
            '● Online</span>'
        )
    return (
        '<span style="background:#ffebee; color:#c62828; border:1px solid #ef9a9a; '
        'border-radius:12px; padding:3px 12px; font-size:12px; font-weight:600;">'
        '● Offline</span>'
    )


def signal_bar(rssi: int | None) -> str:
    """Return an HTML signal strength indicator coloured by RSSI level."""
    if rssi is None:
        return '<span style="color:#aaa;">—</span>'

    if rssi >= -50:
        color, label, bars = "#2e7d32", "Excelente", 4
    elif rssi >= -65:
        color, label, bars = "#1565c0", "Bom", 3
    elif rssi >= -80:
        color, label, bars = "#e65100", "Regular", 2
    else:
        color, label, bars = "#c62828", "Fraco", 1

    filled = "▮" * bars
    empty  = "▯" * (4 - bars)
    return (
        f'<span style="color:{color}; font-size:13px;" title="{rssi} dBm — {label}">'
        f'{filled}<span style="color:#ccc;">{empty}</span>'
        f' <small>{rssi} dBm</small></span>'
    )


# ------------------------------------------------------------------
# Formatting helpers
# ------------------------------------------------------------------

def fmt_bytes(n: int | float | None) -> str:
    """Format a byte count as a human-readable string (B, KB, MB, GB, TB)."""
    if n is None:
        return "—"
    try:
        n = float(n)
    except (TypeError, ValueError):
        return "—"
    if math.isnan(n) or math.isinf(n):
        return "—"
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
    try:
        seconds = int(float(seconds))
    except (TypeError, ValueError):
        return "—"
    if math.isnan(float(seconds)) if isinstance(seconds, float) else False:
        return "—"
    d, rem = divmod(seconds, 86400)
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
    """Return a dict of Plotly layout defaults (clean, theme-neutral)."""
    return {
        "template":       "plotly_white",
        "paper_bgcolor":  "rgba(0,0,0,0)",
        "plot_bgcolor":   "rgba(0,0,0,0)",
        "font":           {"family": "system-ui, sans-serif"},
        "margin":         {"t": 50, "b": 30, "l": 20, "r": 20},
    }
