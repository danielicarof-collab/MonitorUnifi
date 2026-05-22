#!/usr/bin/env python3
"""
UniFi Intelligence Hub — CLI entry point.

Commands:
  python run.py collect       Run the collector daemon (polls indefinitely)
  python run.py collect-once  Run exactly one collection cycle, then exit
  python run.py ui            Launch the Streamlit dashboard
  python run.py init-db       Create / migrate the database schema only
  python run.py diagnose      Test all API endpoints and show a full report
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv
load_dotenv(ROOT / ".env")

from loguru import logger

# ------------------------------------------------------------------
# Logger setup
# ------------------------------------------------------------------
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
LOG_FILE  = os.getenv("LOG_FILE", str(ROOT / "data" / "collector.log"))

logger.remove()
logger.add(sys.stderr, level=LOG_LEVEL, colorize=True,
           format="<green>{time:HH:mm:ss}</green> | <level>{level: <8}</level> | {message}")
logger.add(LOG_FILE, level=LOG_LEVEL, rotation="10 MB", retention="30 days",
           format="{time:YYYY-MM-DD HH:mm:ss} | {level} | {message}")


# ------------------------------------------------------------------
# Shared factory helpers
# ------------------------------------------------------------------

def _build_db():
    from src.database_manager import DatabaseManager
    db_url = os.getenv("DB_URL", f"sqlite:///{ROOT}/data/unifi_hub.db")
    db = DatabaseManager(db_url)
    db.initialize_schema()
    return db


def _build_api():
    from src.api_client import UniFiAPIClient
    host       = os.getenv("UNIFI_HOST")
    username   = os.getenv("UNIFI_USERNAME")
    password   = os.getenv("UNIFI_PASSWORD")
    site       = os.getenv("UNIFI_SITE", "default")
    verify_ssl = os.getenv("UNIFI_VERIFY_SSL", "false").lower() == "true"

    if not all([host, username, password]):
        logger.error(
            "Missing required environment variables: "
            "UNIFI_HOST, UNIFI_USERNAME, UNIFI_PASSWORD.\n"
            "Copy .env.example to .env and fill in your credentials."
        )
        sys.exit(1)

    return UniFiAPIClient(
        host=host, username=username, password=password,
        site=site, verify_ssl=verify_ssl,
    )


def _build_collector(db, api):
    from src.audit_engine import AuditEngine
    from src.collector import DataCollector

    threshold = int(os.getenv("SUSPICIOUS_BLOCKS_THRESHOLD", "5"))
    audit     = AuditEngine(db, suspicious_threshold=threshold)
    limit     = int(os.getenv("EVENTS_FETCH_LIMIT", "3000"))

    return DataCollector(api=api, db=db, audit=audit, events_fetch_limit=limit)


# ------------------------------------------------------------------
# Commands
# ------------------------------------------------------------------

def cmd_init_db() -> None:
    logger.info("Initialising database schema…")
    db = _build_db()
    logger.info("Done.")


def cmd_collect_once() -> None:
    logger.info("Running single collection cycle…")
    db        = _build_db()
    api       = _build_api()
    collector = _build_collector(db, api)
    collector.collect_once()
    api.logout()


def cmd_collect() -> None:
    interval = int(os.getenv("POLL_INTERVAL_SECONDS", "60"))
    logger.info("Starting collector daemon (interval={}s)…", interval)
    db        = _build_db()
    api       = _build_api()
    collector = _build_collector(db, api)
    collector.run_continuous(interval_seconds=interval)


def cmd_diagnose() -> None:
    """Testa todos os endpoints da API e exibe um relatório detalhado."""
    print("\n" + "═" * 62)
    print("  UniFi Intelligence Hub — Diagnóstico de API")
    print("═" * 62)
    api    = _build_api()
    report = api.run_diagnostics()

    print(f"\n  Host        : {report['host']}")
    print(f"  Site (.env) : {report['site_configured']}")
    print(f"  Site real   : {report['site_discovered']}")
    print(f"  Autenticado : {'✅ Sim' if report['authenticated'] else '❌ Não'}")
    print("\n  ── Endpoints ─────────────────────────────────────────")

    ok_count   = 0
    fail_count = 0
    for ep, status in report["endpoints"].items():
        ok = status.startswith("OK")
        icon = "✅" if ok else "❌"
        print(f"  {icon}  {ep:<20} {status}")
        if ok:
            ok_count += 1
        else:
            fail_count += 1

    print("\n  ── Diagnóstico ───────────────────────────────────────")
    syslog_ok = any(
        v.startswith("OK") for k, v in report["endpoints"].items()
        if k.startswith("syslog_")
    )
    events_ok  = report["endpoints"].get("events_v1", "").startswith("OK")

    if fail_count == 0 or (syslog_ok and ok_count >= 5):
        print("  ✅ Sistema pronto! Execute: python run.py collect-once")
        if syslog_ok:
            print("  ✅ System-Log (firmware moderno) acessível — eventos de firewall OK.")
        elif events_ok:
            print("  ✅ Events v1 (firmware legado) acessível.")
    else:
        print(f"  ⚠️  {fail_count} endpoint(s) com problema.\n")

        if not syslog_ok and not events_ok:
            print("  PROBLEMA: eventos de segurança não acessíveis.")
            print("  SOLUÇÕES:")
            print("    A) Verifique o role do usuário: deve ser 'Administrator (Read Only)'")
            print(f"    B) Site correto: UNIFI_SITE={report['site_discovered']}")

        if report["endpoints"].get("health", "").startswith("404"):
            print("  PROBLEMA: /stat/health retornou 404 → UNIFI_SITE incorreto.")
            print(f"    Atualize: UNIFI_SITE={report['site_discovered']}")

    print("\n" + "═" * 62 + "\n")
    api.logout()


def cmd_ui() -> None:
    logger.info("Starting Streamlit dashboard…")
    app_path = str(ROOT / "ui" / "app.py")
    subprocess.run(
        [sys.executable, "-m", "streamlit", "run", app_path,
         "--server.headless", "true",
         "--theme.base", "light",
         "--theme.backgroundColor", "#ffffff",
         "--theme.secondaryBackgroundColor", "#f5f7fa",
         "--theme.textColor", "#1a1a2e",
         "--theme.primaryColor", "#1976d2"],
        check=False,
    )


# ------------------------------------------------------------------
# Entry point
# ------------------------------------------------------------------

COMMANDS = {
    "collect":      cmd_collect,
    "collect-once": cmd_collect_once,
    "ui":           cmd_ui,
    "init-db":      cmd_init_db,
    "diagnose":     cmd_diagnose,
}

if __name__ == "__main__":
    command = sys.argv[1] if len(sys.argv) > 1 else "ui"

    handler = COMMANDS.get(command)
    if handler is None:
        print(__doc__)
        print(f"Erro: comando desconhecido '{command}'")
        print(f"Comandos disponíveis: {', '.join(COMMANDS)}")
        sys.exit(1)

    handler()
