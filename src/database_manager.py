"""
Database manager — schema creation, upserts, and all dashboard queries.

Supports SQLite (default) and PostgreSQL via the DB_URL environment variable.
All timestamps are stored as UTC.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd
from loguru import logger
from sqlalchemy import create_engine, func, text
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.exc import IntegrityError

from src.models import (
    Base, Client, CollectionState, DPITraffic,
    FirewallBlock, Threat, VPNStatus, WANStatus,
)


class DatabaseManager:
    def __init__(self, db_url: str) -> None:
        connect_args = {}
        if db_url.startswith("sqlite"):
            # Allow multi-thread access from the Streamlit + collector processes
            connect_args = {"check_same_thread": False}

        self._engine = create_engine(db_url, connect_args=connect_args, echo=False)
        self._Session = sessionmaker(bind=self._engine)
        logger.info("Database engine created: {}", db_url.split("@")[-1])

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def initialize_schema(self) -> None:
        Base.metadata.create_all(self._engine)
        self._migrate_schema()
        logger.info("Database schema initialised / verified")

    def _migrate_schema(self) -> None:
        """
        Aplica migrações incrementais que o create_all não executa
        (colunas novas em tabelas já existentes).
        """
        migrations = [
            # v2 — campos adicionados para suporte ao system-log
            "ALTER TABLE firewall_blocks ADD COLUMN severity  VARCHAR(20)",
            "ALTER TABLE firewall_blocks ADD COLUMN raw_message TEXT",
            "ALTER TABLE firewall_blocks ADD COLUMN source     VARCHAR(20)",
            # raw_event_id ampliado para UUIDs (128 chars)
            # SQLite não suporta ALTER COLUMN — ignoramos silenciosamente
        ]
        with self._engine.connect() as conn:
            for sql in migrations:
                try:
                    conn.execute(text(sql))
                    conn.commit()
                except Exception:
                    pass  # coluna já existe ou banco não suporta — ok

    def _session(self) -> Session:
        return self._Session()

    # ------------------------------------------------------------------
    # Upserts (writes from collector)
    # ------------------------------------------------------------------

    def upsert_client(self, data: Dict[str, Any]) -> None:
        """Insert or update a client record keyed by MAC address."""
        mac = data.get("mac", "").lower()
        if not mac:
            return

        with self._session() as sess:
            client = sess.query(Client).filter_by(mac=mac).first()
            if client is None:
                client = Client(mac=mac, first_seen=datetime.utcnow())
                sess.add(client)

            client.name     = data.get("name") or data.get("alias") or client.name
            client.hostname = data.get("hostname") or client.hostname
            client.ip       = data.get("ip") or client.ip
            client.vendor   = data.get("oui") or client.vendor
            client.last_seen = datetime.utcnow()
            sess.commit()

    def insert_wan_status(self, data: Dict[str, Any]) -> None:
        with self._session() as sess:
            rec = WANStatus(
                interface  = data.get("interface", "WAN"),
                status     = data.get("status", "unknown"),
                uptime     = data.get("uptime"),
                latency_ms = data.get("latency"),
                rx_bytes   = data.get("rx_bytes"),
                tx_bytes   = data.get("tx_bytes"),
                wan_ip     = data.get("wan_ip"),
                timestamp  = data.get("timestamp", datetime.utcnow()),
            )
            sess.add(rec)
            sess.commit()

    def insert_firewall_block(self, data: Dict[str, Any]) -> bool:
        """Returns True if the record was new (not a duplicate)."""
        raw_id = data.get("raw_event_id")
        if not raw_id:
            return False

        with self._session() as sess:
            exists = sess.query(FirewallBlock).filter_by(raw_event_id=raw_id).first()
            if exists:
                return False

            rec = FirewallBlock(
                raw_event_id = raw_id,
                timestamp    = data.get("timestamp", datetime.utcnow()),
                client_mac   = (data.get("client_mac") or "").lower() or None,
                client_ip    = data.get("client_ip"),
                client_name  = data.get("client_name"),
                rule_name    = data.get("rule_name"),
                rule_type    = data.get("rule_type", "firewall_rule"),
                destination  = data.get("destination"),
                dst_port     = data.get("dst_port"),
                protocol     = data.get("protocol"),
                category     = data.get("category"),
                severity     = data.get("severity", "medium"),
                raw_message  = data.get("raw_message"),
                source       = data.get("source", "unknown"),
            )
            sess.add(rec)
            try:
                sess.commit()
                # Update the client's running block counter
                if rec.client_mac:
                    self._increment_block_counter(rec.client_mac)
                return True
            except IntegrityError:
                sess.rollback()
                return False

    def insert_threat(self, data: Dict[str, Any]) -> bool:
        raw_id = data.get("raw_event_id")
        if not raw_id:
            return False

        with self._session() as sess:
            if sess.query(Threat).filter_by(raw_event_id=raw_id).first():
                return False

            rec = Threat(
                raw_event_id = raw_id,
                timestamp    = data.get("timestamp", datetime.utcnow()),
                client_mac   = (data.get("client_mac") or "").lower() or None,
                client_ip    = data.get("client_ip"),
                client_name  = data.get("client_name"),
                threat_type  = data.get("threat_type", "Unknown"),
                severity     = data.get("severity", "medium"),
                description  = data.get("description"),
                action_taken = data.get("action_taken"),
            )
            sess.add(rec)
            try:
                sess.commit()
                return True
            except IntegrityError:
                sess.rollback()
                return False

    def insert_dpi_snapshot(self, records: List[Dict[str, Any]]) -> None:
        with self._session() as sess:
            ts = datetime.utcnow()
            for r in records:
                sess.add(DPITraffic(
                    timestamp   = ts,
                    client_mac  = r["client_mac"].lower(),
                    category    = r["category"],
                    application = r.get("application", ""),
                    rx_bytes    = r.get("rx_bytes", 0),
                    tx_bytes    = r.get("tx_bytes", 0),
                ))
            sess.commit()

    def batch_insert_firewall_blocks(self, records: List[Dict[str, Any]]) -> int:
        """
        Insere múltiplos bloqueios em UMA transação (bulk insert).

        Muito mais rápido que inserções individuais — para páginas de 500
        eventos, reduz de ~500 commits para 2 queries (SELECT + INSERT).
        Retorna o número de novos registros inseridos (excluindo duplicatas).
        """
        if not records:
            return 0

        raw_ids = [r["raw_event_id"] for r in records if r.get("raw_event_id")]
        if not raw_ids:
            return 0

        with self._session() as sess:
            # Verifica quais IDs já existem — 1 query para todos
            existing = set(
                row[0] for row in
                sess.query(FirewallBlock.raw_event_id)
                   .filter(FirewallBlock.raw_event_id.in_(raw_ids))
                   .all()
            )

            new_objs: List[FirewallBlock] = []
            macs: List[str] = []

            for data in records:
                raw_id = data.get("raw_event_id")
                if not raw_id or raw_id in existing:
                    continue
                mac = (data.get("client_mac") or "").lower() or None
                new_objs.append(FirewallBlock(
                    raw_event_id = raw_id,
                    timestamp    = data.get("timestamp", datetime.utcnow()),
                    client_mac   = mac,
                    client_ip    = data.get("client_ip"),
                    client_name  = data.get("client_name"),
                    rule_name    = data.get("rule_name"),
                    rule_type    = data.get("rule_type", "firewall_rule"),
                    destination  = data.get("destination"),
                    dst_port     = data.get("dst_port"),
                    protocol     = data.get("protocol"),
                    category     = data.get("category"),
                    severity     = data.get("severity", "medium"),
                    raw_message  = data.get("raw_message"),
                    source       = data.get("source", "unknown"),
                ))
                if mac:
                    macs.append(mac)

            if new_objs:
                sess.bulk_save_objects(new_objs)
                sess.commit()

            if macs:
                self._batch_increment_counters(macs)

            return len(new_objs)

    def _batch_increment_counters(self, macs: List[str]) -> None:
        """Incrementa total_blocks para múltiplos MACs em uma transação."""
        from collections import Counter
        counts = Counter(macs)
        with self._session() as sess:
            for mac, n in counts.items():
                client = sess.query(Client).filter_by(mac=mac).first()
                if client:
                    client.total_blocks = (client.total_blocks or 0) + n
            sess.commit()

    def _increment_block_counter(self, mac: str) -> None:
        with self._session() as sess:
            client = sess.query(Client).filter_by(mac=mac.lower()).first()
            if client:
                client.total_blocks = (client.total_blocks or 0) + 1
                sess.commit()

    # ------------------------------------------------------------------
    # Suspicious-device management
    # ------------------------------------------------------------------

    def mark_suspicious(self, mac: str, reason: str) -> None:
        with self._session() as sess:
            client = sess.query(Client).filter_by(mac=mac.lower()).first()
            if client and not client.is_suspicious:
                client.is_suspicious = True
                client.suspicious_reason = reason
                sess.commit()
                logger.warning("Marked {} as suspicious: {}", mac, reason)

    # ------------------------------------------------------------------
    # Dashboard queries
    # ------------------------------------------------------------------

    def get_top_violators(self, days: int = 30, limit: int = 10) -> pd.DataFrame:
        """Ranking of clients with the most firewall blocks in the past N days."""
        since = datetime.utcnow() - timedelta(days=days)
        with self._session() as sess:
            rows = (
                sess.query(
                    FirewallBlock.client_mac,
                    FirewallBlock.client_name,
                    FirewallBlock.client_ip,
                    func.count(FirewallBlock.id).label("total_blocks"),
                    func.max(FirewallBlock.timestamp).label("last_seen"),
                )
                .filter(FirewallBlock.timestamp >= since)
                .group_by(FirewallBlock.client_mac)
                .order_by(func.count(FirewallBlock.id).desc())
                .limit(limit)
                .all()
            )
        if not rows:
            return pd.DataFrame(columns=["mac", "name", "ip", "total_blocks", "last_seen"])
        return pd.DataFrame(rows, columns=["mac", "name", "ip", "total_blocks", "last_seen"])

    def get_recent_blocks(self, limit: int = 200) -> pd.DataFrame:
        with self._session() as sess:
            rows = (
                sess.query(FirewallBlock)
                .order_by(FirewallBlock.timestamp.desc())
                .limit(limit)
                .all()
            )
        if not rows:
            return pd.DataFrame()
        return pd.DataFrame([{
            "timestamp":   r.timestamp,
            "client_name": r.client_name or r.client_mac or "Unknown",
            "client_mac":  r.client_mac,
            "client_ip":   r.client_ip,
            "rule_name":   r.rule_name,
            "rule_type":   r.rule_type,
            "destination": r.destination,
            "category":    r.category,
        } for r in rows])

    def get_blocks_by_category(self, days: int = 30) -> pd.DataFrame:
        since = datetime.utcnow() - timedelta(days=days)
        with self._session() as sess:
            rows = (
                sess.query(
                    FirewallBlock.category,
                    func.count(FirewallBlock.id).label("count"),
                )
                .filter(FirewallBlock.timestamp >= since, FirewallBlock.category.isnot(None))
                .group_by(FirewallBlock.category)
                .order_by(func.count(FirewallBlock.id).desc())
                .all()
            )
        return pd.DataFrame(rows, columns=["category", "count"]) if rows else pd.DataFrame()

    def get_threat_timeline(self, days: int = 7) -> pd.DataFrame:
        """Threat count per hour for the past N days."""
        since = datetime.utcnow() - timedelta(days=days)
        with self._session() as sess:
            rows = (
                sess.query(Threat.timestamp, Threat.severity, Threat.threat_type)
                .filter(Threat.timestamp >= since)
                .order_by(Threat.timestamp.asc())
                .all()
            )
        if not rows:
            return pd.DataFrame(columns=["timestamp", "severity", "threat_type"])
        df = pd.DataFrame(rows, columns=["timestamp", "severity", "threat_type"])
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        return df

    def get_block_timeline(self, days: int = 7) -> pd.DataFrame:
        since = datetime.utcnow() - timedelta(days=days)
        with self._session() as sess:
            rows = (
                sess.query(FirewallBlock.timestamp, FirewallBlock.rule_type, FirewallBlock.category)
                .filter(FirewallBlock.timestamp >= since)
                .order_by(FirewallBlock.timestamp.asc())
                .all()
            )
        if not rows:
            return pd.DataFrame(columns=["timestamp", "rule_type", "category"])
        df = pd.DataFrame(rows, columns=["timestamp", "rule_type", "category"])
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        return df

    def get_suspicious_clients(self) -> pd.DataFrame:
        with self._session() as sess:
            rows = (
                sess.query(Client)
                .filter_by(is_suspicious=True)
                .order_by(Client.total_blocks.desc())
                .all()
            )
        if not rows:
            return pd.DataFrame()
        return pd.DataFrame([{
            "mac":              r.mac,
            "name":             r.display_name(),
            "ip":               r.ip,
            "total_blocks":     r.total_blocks,
            "reason":           r.suspicious_reason,
            "last_seen":        r.last_seen,
        } for r in rows])

    def get_wan_uptime_stats(
        self, year: int, month: int
    ) -> Dict[str, Any]:
        """
        Compute WAN uptime percentage for a calendar month.
        We count samples where status == 'ok' vs total samples.
        """
        start = datetime(year, month, 1)
        # last day of month
        if month == 12:
            end = datetime(year + 1, 1, 1)
        else:
            end = datetime(year, month + 1, 1)

        with self._session() as sess:
            total = (
                sess.query(func.count(WANStatus.id))
                .filter(WANStatus.timestamp >= start, WANStatus.timestamp < end)
                .scalar()
            ) or 0

            up = (
                sess.query(func.count(WANStatus.id))
                .filter(
                    WANStatus.timestamp >= start,
                    WANStatus.timestamp < end,
                    WANStatus.status == "ok",
                )
                .scalar()
            ) or 0

            avg_latency = (
                sess.query(func.avg(WANStatus.latency_ms))
                .filter(
                    WANStatus.timestamp >= start,
                    WANStatus.timestamp < end,
                    WANStatus.status == "ok",
                )
                .scalar()
            )

        uptime_pct = round((up / total * 100), 3) if total > 0 else None
        return {
            "year":        year,
            "month":       month,
            "total_samples": total,
            "up_samples":  up,
            "uptime_pct":  uptime_pct,
            "avg_latency_ms": round(avg_latency, 1) if avg_latency else None,
        }

    def get_latest_wan_status(self) -> pd.DataFrame:
        with self._session() as sess:
            subq = (
                sess.query(
                    WANStatus.interface,
                    func.max(WANStatus.timestamp).label("max_ts"),
                )
                .group_by(WANStatus.interface)
                .subquery()
            )
            rows = (
                sess.query(WANStatus)
                .join(
                    subq,
                    (WANStatus.interface == subq.c.interface)
                    & (WANStatus.timestamp == subq.c.max_ts),
                )
                .all()
            )
        if not rows:
            return pd.DataFrame()
        return pd.DataFrame([{
            "interface":   r.interface,
            "status":      r.status,
            "latency_ms":  r.latency_ms,
            "uptime":      r.uptime,
            "wan_ip":      r.wan_ip,
            "rx_bytes":    r.rx_bytes,
            "tx_bytes":    r.tx_bytes,
            "timestamp":   r.timestamp,
        } for r in rows])

    def get_top_threats(self, days: int = 30, limit: int = 10) -> pd.DataFrame:
        since = datetime.utcnow() - timedelta(days=days)
        with self._session() as sess:
            rows = (
                sess.query(Threat)
                .filter(Threat.timestamp >= since)
                .order_by(Threat.timestamp.desc())
                .limit(limit)
                .all()
            )
        if not rows:
            return pd.DataFrame()
        return pd.DataFrame([{
            "timestamp":   r.timestamp,
            "client_name": r.client_name or r.client_mac or "Unknown",
            "threat_type": r.threat_type,
            "severity":    r.severity,
            "description": r.description,
            "action":      r.action_taken,
        } for r in rows])

    def get_summary_stats(self, days: int = 30) -> Dict[str, int]:
        since = datetime.utcnow() - timedelta(days=days)
        with self._session() as sess:
            return {
                "total_blocks":       sess.query(func.count(FirewallBlock.id)).filter(FirewallBlock.timestamp >= since).scalar() or 0,
                "unique_violators":   sess.query(func.count(func.distinct(FirewallBlock.client_mac))).filter(FirewallBlock.timestamp >= since).scalar() or 0,
                "total_threats":      sess.query(func.count(Threat.id)).filter(Threat.timestamp >= since).scalar() or 0,
                "suspicious_devices": sess.query(func.count(Client.id)).filter_by(is_suspicious=True).scalar() or 0,
            }

    def get_client_name(self, mac: str) -> Optional[str]:
        with self._session() as sess:
            c = sess.query(Client).filter_by(mac=mac.lower()).first()
            return c.display_name() if c else None

    def get_all_clients_map(self) -> Dict[str, str]:
        """Returns {mac: display_name} for the entire clients table."""
        with self._session() as sess:
            rows = sess.query(Client.mac, Client.name, Client.hostname).all()
        result = {}
        for mac, name, hostname in rows:
            result[mac] = name or hostname or mac
        return result

    def get_recent_blocks_for_mac(
        self, mac: str, since: datetime
    ) -> int:
        with self._session() as sess:
            return (
                sess.query(func.count(FirewallBlock.id))
                .filter(
                    FirewallBlock.client_mac == mac.lower(),
                    FirewallBlock.timestamp >= since,
                )
                .scalar()
            ) or 0

    # ------------------------------------------------------------------
    # Collection state — rastreamento de última coleta incremental
    # ------------------------------------------------------------------

    def get_last_event_timestamp(self) -> Optional[int]:
        """
        Retorna o timestamp (Unix ms) do evento mais recente já coletado
        via system-log, ou None se for a primeira coleta.
        """
        with self._session() as sess:
            row = sess.query(CollectionState).filter_by(
                key="last_syslog_ts_ms"
            ).first()
            if row and row.value:
                try:
                    return int(row.value)
                except ValueError:
                    pass
        return None

    def set_last_event_timestamp(self, ts_ms: int) -> None:
        """Salva o timestamp (Unix ms) do evento mais recente coletado."""
        with self._session() as sess:
            row = sess.query(CollectionState).filter_by(
                key="last_syslog_ts_ms"
            ).first()
            if row:
                row.value      = str(ts_ms)
                row.updated_at = datetime.utcnow()
            else:
                sess.add(CollectionState(
                    key="last_syslog_ts_ms",
                    value=str(ts_ms),
                ))
            sess.commit()
