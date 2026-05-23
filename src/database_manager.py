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
    Base, Client, ClientSnapshot, APStat, RogueAP,
    CollectionState, DPITraffic, FirewallBlock, Threat, VPNStatus, WANStatus,
    DeviceStat, NetworkStat, PortStat, SpeedtestResult,
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
            # v2 — system-log support
            "ALTER TABLE firewall_blocks ADD COLUMN severity  VARCHAR(20)",
            "ALTER TABLE firewall_blocks ADD COLUMN raw_message TEXT",
            "ALTER TABLE firewall_blocks ADD COLUMN source     VARCHAR(20)",
            # v3 — device fingerprint fields
            "ALTER TABLE clients ADD COLUMN device_type VARCHAR(50)",
            "ALTER TABLE clients ADD COLUMN os_name VARCHAR(100)",
            "ALTER TABLE clients ADD COLUMN dev_family VARCHAR(100)",
            # v4 — temperature columns in device_stats
            "ALTER TABLE device_stats ADD COLUMN temp_cpu FLOAT",
            "ALTER TABLE device_stats ADD COLUMN temp_board FLOAT",
            "ALTER TABLE device_stats ADD COLUMN temp_phy FLOAT",
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

            client.name       = data.get("name") or data.get("alias") or client.name
            client.hostname   = data.get("hostname") or client.hostname
            client.ip         = data.get("ip") or client.ip
            client.vendor     = data.get("oui") or client.vendor
            client.device_type = data.get("device_type") or client.device_type
            client.os_name    = data.get("os_name") or client.os_name
            client.dev_family = data.get("dev_family") or client.dev_family
            client.last_seen  = datetime.utcnow()
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

    # ------------------------------------------------------------------
    # ClientSnapshot methods
    # ------------------------------------------------------------------

    def insert_client_snapshots(self, records: List[Dict[str, Any]]) -> None:
        with self._session() as sess:
            ts = datetime.utcnow()
            for r in records:
                sess.add(ClientSnapshot(
                    timestamp     = ts,
                    client_mac    = r["client_mac"],
                    signal        = r.get("signal"),
                    noise         = r.get("noise"),
                    tx_rate       = r.get("tx_rate"),
                    rx_rate       = r.get("rx_rate"),
                    satisfaction  = r.get("satisfaction"),
                    tx_bytes_rate = r.get("tx_bytes_rate"),
                    rx_bytes_rate = r.get("rx_bytes_rate"),
                    ap_mac        = r.get("ap_mac"),
                    radio_band    = r.get("radio_band"),
                    channel       = r.get("channel"),
                    essid         = r.get("essid"),
                    is_wired      = r.get("is_wired", False),
                    uptime_sec    = r.get("uptime_sec"),
                ))
            sess.commit()

    def get_latest_client_snapshots(self) -> pd.DataFrame:
        """Snapshot mais recente de cada cliente."""
        with self._session() as sess:
            subq = (
                sess.query(
                    ClientSnapshot.client_mac,
                    func.max(ClientSnapshot.timestamp).label("max_ts"),
                )
                .group_by(ClientSnapshot.client_mac)
                .subquery()
            )
            rows = (
                sess.query(ClientSnapshot, Client)
                .join(subq, (ClientSnapshot.client_mac == subq.c.client_mac) &
                            (ClientSnapshot.timestamp == subq.c.max_ts))
                .outerjoin(Client, Client.mac == ClientSnapshot.client_mac)
                .all()
            )
        if not rows:
            return pd.DataFrame()
        result = []
        for snap, client in rows:
            result.append({
                "mac":           snap.client_mac,
                "name":          (client.name or client.hostname or snap.client_mac) if client else snap.client_mac,
                "device_type":   client.device_type if client else "unknown",
                "os_name":       client.os_name if client else None,
                "vendor":        client.vendor if client else None,
                "ip":            client.ip if client else None,
                "signal":        snap.signal,
                "noise":         snap.noise,
                "tx_rate":       snap.tx_rate,
                "rx_rate":       snap.rx_rate,
                "satisfaction":  snap.satisfaction,
                "tx_bytes_rate": snap.tx_bytes_rate,
                "rx_bytes_rate": snap.rx_bytes_rate,
                "ap_mac":        snap.ap_mac,
                "radio_band":    snap.radio_band,
                "channel":       snap.channel,
                "essid":         snap.essid,
                "is_wired":      snap.is_wired,
                "uptime_sec":    snap.uptime_sec,
                "timestamp":     snap.timestamp,
            })
        return pd.DataFrame(result)

    def get_all_clients(self) -> pd.DataFrame:
        """Todos os clientes conhecidos."""
        with self._session() as sess:
            rows = sess.query(Client).order_by(Client.last_seen.desc()).all()
        if not rows:
            return pd.DataFrame()
        return pd.DataFrame([{
            "mac":           r.mac,
            "name":          r.display_name(),
            "ip":            r.ip,
            "vendor":        r.vendor,
            "device_type":   r.device_type or "unknown",
            "os_name":       r.os_name,
            "dev_family":    r.dev_family,
            "first_seen":    r.first_seen,
            "last_seen":     r.last_seen,
            "is_suspicious": r.is_suspicious,
            "total_blocks":  r.total_blocks,
        } for r in rows])

    def get_device_type_counts(self) -> pd.DataFrame:
        with self._session() as sess:
            rows = (
                sess.query(Client.device_type, func.count(Client.id).label("count"))
                .group_by(Client.device_type)
                .all()
            )
        if not rows:
            return pd.DataFrame(columns=["device_type", "count"])
        return pd.DataFrame(rows, columns=["device_type", "count"])

    def get_top_bandwidth_consumers(self, limit: int = 10) -> pd.DataFrame:
        """Top clientes por taxa de bytes atual (snapshot mais recente de cada um)."""
        df = self.get_latest_client_snapshots()
        if df.empty:
            return pd.DataFrame()
        df["total_rate"] = (df["tx_bytes_rate"].fillna(0) + df["rx_bytes_rate"].fillna(0))
        return df.nlargest(limit, "total_rate")[
            ["mac", "name", "device_type", "ip",
             "tx_bytes_rate", "rx_bytes_rate", "total_rate",
             "radio_band", "essid"]
        ]

    # ------------------------------------------------------------------
    # APStat methods
    # ------------------------------------------------------------------

    def insert_ap_stat(self, data: Dict[str, Any]) -> None:
        with self._session() as sess:
            sess.add(APStat(
                timestamp       = data.get("timestamp", datetime.utcnow()),
                mac             = data["mac"],
                name            = data.get("name"),
                model           = data.get("model"),
                ip              = data.get("ip"),
                num_clients     = data.get("num_clients", 0),
                num_clients_24g = data.get("num_clients_24g", 0),
                num_clients_5g  = data.get("num_clients_5g", 0),
                num_clients_6g  = data.get("num_clients_6g", 0),
                tx_bytes_rate   = data.get("tx_bytes_rate"),
                rx_bytes_rate   = data.get("rx_bytes_rate"),
                satisfaction    = data.get("satisfaction"),
                uptime_sec      = data.get("uptime_sec"),
                channel_24g     = data.get("channel_24g"),
                channel_5g      = data.get("channel_5g"),
            ))
            sess.commit()

    def get_latest_ap_stats(self) -> pd.DataFrame:
        with self._session() as sess:
            subq = (
                sess.query(APStat.mac, func.max(APStat.timestamp).label("max_ts"))
                .group_by(APStat.mac)
                .subquery()
            )
            rows = (
                sess.query(APStat)
                .join(subq, (APStat.mac == subq.c.mac) & (APStat.timestamp == subq.c.max_ts))
                .all()
            )
        if not rows:
            return pd.DataFrame()
        return pd.DataFrame([{
            "mac":             r.mac,
            "name":            r.name or r.mac,
            "model":           r.model,
            "ip":              r.ip,
            "num_clients":     r.num_clients,
            "num_clients_24g": r.num_clients_24g,
            "num_clients_5g":  r.num_clients_5g,
            "num_clients_6g":  r.num_clients_6g,
            "tx_bytes_rate":   r.tx_bytes_rate,
            "rx_bytes_rate":   r.rx_bytes_rate,
            "satisfaction":    r.satisfaction,
            "uptime_sec":      r.uptime_sec,
            "channel_24g":     r.channel_24g,
            "channel_5g":      r.channel_5g,
            "timestamp":       r.timestamp,
        } for r in rows])

    # ------------------------------------------------------------------
    # RogueAP methods
    # ------------------------------------------------------------------

    def upsert_rogue_ap(self, data: Dict[str, Any]) -> None:
        bssid = data.get("bssid", "").lower()
        if not bssid:
            return
        with self._session() as sess:
            rec = sess.query(RogueAP).filter_by(bssid=bssid).first()
            if rec is None:
                rec = RogueAP(bssid=bssid, first_seen=datetime.utcnow())
                sess.add(rec)
            rec.ssid      = data.get("ssid")
            rec.channel   = data.get("channel")
            rec.signal    = data.get("signal")
            rec.security  = data.get("security")
            rec.is_rogue  = data.get("is_rogue", True)
            rec.ap_mac    = data.get("ap_mac")
            rec.last_seen = datetime.utcnow()
            sess.commit()

    def get_rogue_aps(self) -> pd.DataFrame:
        with self._session() as sess:
            rows = sess.query(RogueAP).order_by(RogueAP.last_seen.desc()).all()
        if not rows:
            return pd.DataFrame()
        return pd.DataFrame([{
            "bssid":      r.bssid,
            "ssid":       r.ssid or "—",
            "channel":    r.channel,
            "signal":     r.signal,
            "security":   r.security or "—",
            "is_rogue":   r.is_rogue,
            "ap_mac":     r.ap_mac,
            "first_seen": r.first_seen,
            "last_seen":  r.last_seen,
        } for r in rows])

    def get_online_clients_count(self, minutes: int = 5) -> int:
        """Conta clientes com snapshot nos últimos N minutos."""
        cutoff = datetime.utcnow() - timedelta(minutes=minutes)
        with self._session() as sess:
            subq = (
                sess.query(func.max(ClientSnapshot.timestamp).label("max_ts"))
                .group_by(ClientSnapshot.client_mac)
                .subquery()
            )
            count = (
                sess.query(func.count())
                .select_from(subq)
                .filter(subq.c.max_ts >= cutoff)
                .scalar()
            ) or 0
        return count

    def get_summary_stats(self, days: int = 30) -> Dict[str, int]:
        since = datetime.utcnow() - timedelta(days=days)
        with self._session() as sess:
            stats = {
                "total_blocks":       sess.query(func.count(FirewallBlock.id)).filter(FirewallBlock.timestamp >= since).scalar() or 0,
                "unique_violators":   sess.query(func.count(func.distinct(FirewallBlock.client_mac))).filter(FirewallBlock.timestamp >= since).scalar() or 0,
                "total_threats":      sess.query(func.count(Threat.id)).filter(Threat.timestamp >= since).scalar() or 0,
                "suspicious_devices": sess.query(func.count(Client.id)).filter_by(is_suspicious=True).scalar() or 0,
            }
        stats["online_devices"] = self.get_online_clients_count(minutes=5)
        return stats

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

    # ------------------------------------------------------------------
    # Device Statistics (NEW)
    # ------------------------------------------------------------------

    def insert_device_stat(self, data: Dict[str, Any]) -> bool:
        """Insert a device statistic snapshot."""
        device_mac = data.get("device_mac", "").lower()
        if not device_mac:
            return False

        try:
            with self._session() as sess:
                rec = DeviceStat(
                    timestamp               = data.get("timestamp", datetime.utcnow()),
                    device_mac              = device_mac,
                    device_name             = data.get("device_name"),
                    device_model            = data.get("device_model"),
                    device_ip               = data.get("device_ip"),
                    cpu_utilization_pct     = data.get("cpu_utilization_pct"),
                    memory_utilization_pct  = data.get("memory_utilization_pct"),
                    load_average_1min       = data.get("load_average_1min"),
                    load_average_5min       = data.get("load_average_5min"),
                    load_average_15min      = data.get("load_average_15min"),
                    uptime_sec              = data.get("uptime_sec"),
                    last_heartbeat_at       = data.get("last_heartbeat_at"),
                    temp_cpu                = data.get("temp_cpu"),
                    temp_board              = data.get("temp_board"),
                    temp_phy                = data.get("temp_phy"),
                    tx_retries_pct_24g      = data.get("tx_retries_pct_24g"),
                    tx_retries_pct_5g       = data.get("tx_retries_pct_5g"),
                    tx_retries_pct_6g       = data.get("tx_retries_pct_6g"),
                    frequency_24g           = data.get("frequency_24g"),
                    frequency_5g            = data.get("frequency_5g"),
                    frequency_6g            = data.get("frequency_6g"),
                    tx_rate_bps             = data.get("tx_rate_bps"),
                    rx_rate_bps             = data.get("rx_rate_bps"),
                )
                sess.add(rec)
                sess.commit()
                return True
        except Exception as exc:
            logger.warning("Failed to insert device stat: {}", exc)
            return False

    def get_device_stats(self, device_mac: str, hours: int = 24) -> pd.DataFrame:
        """Get historical device statistics."""
        since = datetime.utcnow() - timedelta(hours=hours)
        with self._session() as sess:
            rows = (
                sess.query(DeviceStat)
                .filter(
                    DeviceStat.device_mac == device_mac.lower(),
                    DeviceStat.timestamp >= since
                )
                .order_by(DeviceStat.timestamp.asc())
                .all()
            )

        if not rows:
            return pd.DataFrame()

        return pd.DataFrame([{
            "timestamp":      r.timestamp,
            "cpu_pct":        r.cpu_utilization_pct,
            "memory_pct":     r.memory_utilization_pct,
            "load_1min":      r.load_average_1min,
            "load_5min":      r.load_average_5min,
            "load_15min":     r.load_average_15min,
            "temp_cpu":       r.temp_cpu,
            "temp_board":     r.temp_board,
            "temp_phy":       r.temp_phy,
            "tx_retries_24g": r.tx_retries_pct_24g,
            "tx_retries_5g":  r.tx_retries_pct_5g,
            "tx_retries_6g":  r.tx_retries_pct_6g,
        } for r in rows])

    def get_latest_device_stat(self) -> pd.DataFrame:
        """Most recent hardware snapshot for every monitored device."""
        with self._session() as sess:
            subq = (
                sess.query(
                    DeviceStat.device_mac,
                    func.max(DeviceStat.timestamp).label("max_ts"),
                )
                .group_by(DeviceStat.device_mac)
                .subquery()
            )
            rows = (
                sess.query(DeviceStat)
                .join(
                    subq,
                    (DeviceStat.device_mac == subq.c.device_mac)
                    & (DeviceStat.timestamp == subq.c.max_ts),
                )
                .all()
            )
        if not rows:
            return pd.DataFrame()
        return pd.DataFrame([{
            "device_mac":   r.device_mac,
            "device_name":  r.device_name or r.device_mac,
            "device_model": r.device_model,
            "cpu_pct":      r.cpu_utilization_pct,
            "memory_pct":   r.memory_utilization_pct,
            "temp_cpu":     r.temp_cpu,
            "temp_board":   r.temp_board,
            "temp_phy":     r.temp_phy,
            "uptime_sec":   r.uptime_sec,
            "timestamp":    r.timestamp,
        } for r in rows])

    # ------------------------------------------------------------------
    # Port Statistics (NEW)
    # ------------------------------------------------------------------

    def insert_port_stats(self, records: List[Dict[str, Any]]) -> None:
        with self._session() as sess:
            ts = datetime.utcnow()
            for r in records:
                sess.add(PortStat(
                    timestamp      = ts,
                    device_mac     = r["device_mac"].lower(),
                    port_idx       = r.get("port_idx"),
                    port_name      = r.get("port_name"),
                    speed          = r.get("speed"),
                    is_up          = r.get("is_up"),
                    rx_bytes       = r.get("rx_bytes"),
                    tx_bytes       = r.get("tx_bytes"),
                    rx_bytes_rate  = r.get("rx_bytes_rate"),
                    tx_bytes_rate  = r.get("tx_bytes_rate"),
                    rx_errors      = r.get("rx_errors"),
                    tx_errors      = r.get("tx_errors"),
                    rx_dropped     = r.get("rx_dropped"),
                    tx_dropped     = r.get("tx_dropped"),
                    rx_multicast   = r.get("rx_multicast"),
                    poe_power_w    = r.get("poe_power_w"),
                ))
            sess.commit()

    def get_latest_port_stats(self, device_mac: str) -> pd.DataFrame:
        """Latest port snapshot for a device, one row per port."""
        with self._session() as sess:
            subq = (
                sess.query(
                    PortStat.device_mac,
                    func.max(PortStat.timestamp).label("max_ts"),
                )
                .filter(PortStat.device_mac == device_mac.lower())
                .group_by(PortStat.device_mac)
                .subquery()
            )
            rows = (
                sess.query(PortStat)
                .join(
                    subq,
                    (PortStat.device_mac == subq.c.device_mac)
                    & (PortStat.timestamp == subq.c.max_ts),
                )
                .order_by(PortStat.port_idx)
                .all()
            )
        if not rows:
            return pd.DataFrame()
        return pd.DataFrame([{
            "port_idx":     r.port_idx,
            "port_name":    r.port_name or f"Port {r.port_idx}",
            "speed":        r.speed,
            "is_up":        r.is_up,
            "rx_bytes":     r.rx_bytes,
            "tx_bytes":     r.tx_bytes,
            "rx_bytes_rate": r.rx_bytes_rate,
            "tx_bytes_rate": r.tx_bytes_rate,
            "rx_errors":    r.rx_errors,
            "tx_errors":    r.tx_errors,
            "rx_dropped":   r.rx_dropped,
            "tx_dropped":   r.tx_dropped,
            "poe_power_w":  r.poe_power_w,
        } for r in rows])

    # ------------------------------------------------------------------
    # Speedtest Results (NEW)
    # ------------------------------------------------------------------

    def insert_speedtest_result(self, data: Dict[str, Any]) -> None:
        with self._session() as sess:
            sess.add(SpeedtestResult(
                timestamp     = data.get("timestamp", datetime.utcnow()),
                interface     = data.get("interface", "WAN"),
                ping_ms       = data.get("ping_ms"),
                download_mbps = data.get("download_mbps"),
                upload_mbps   = data.get("upload_mbps"),
                isp_name      = data.get("isp_name"),
                isp_org       = data.get("isp_org"),
                wan_ip        = data.get("wan_ip"),
            ))
            sess.commit()

    def get_speedtest_history(self, days: int = 30) -> pd.DataFrame:
        since = datetime.utcnow() - timedelta(days=days)
        with self._session() as sess:
            rows = (
                sess.query(SpeedtestResult)
                .filter(SpeedtestResult.timestamp >= since)
                .order_by(SpeedtestResult.timestamp.asc())
                .all()
            )
        if not rows:
            return pd.DataFrame()
        return pd.DataFrame([{
            "timestamp":     r.timestamp,
            "interface":     r.interface,
            "ping_ms":       r.ping_ms,
            "download_mbps": r.download_mbps,
            "upload_mbps":   r.upload_mbps,
            "isp_name":      r.isp_name,
            "wan_ip":        r.wan_ip,
        } for r in rows])

    def get_latest_speedtest(self) -> Optional[Dict[str, Any]]:
        with self._session() as sess:
            row = (
                sess.query(SpeedtestResult)
                .order_by(SpeedtestResult.timestamp.desc())
                .first()
            )
        if not row:
            return None
        return {
            "timestamp":     row.timestamp,
            "interface":     row.interface,
            "ping_ms":       row.ping_ms,
            "download_mbps": row.download_mbps,
            "upload_mbps":   row.upload_mbps,
            "isp_name":      row.isp_name,
            "isp_org":       row.isp_org,
            "wan_ip":        row.wan_ip,
        }

    # ------------------------------------------------------------------
    # Network Statistics (NEW)
    # ------------------------------------------------------------------

    def insert_network_stat(self, data: Dict[str, Any]) -> bool:
        """Insert a network statistic snapshot."""
        network_name = data.get("network_name")
        if not network_name:
            return False

        try:
            with self._session() as sess:
                rec = NetworkStat(
                    timestamp       = data.get("timestamp", datetime.utcnow()),
                    network_name    = network_name,
                    network_id      = data.get("network_id"),
                    ip_subnet       = data.get("ip_subnet"),
                    num_clients     = data.get("num_clients", 0),
                    up_bytes        = data.get("up_bytes", 0),
                    down_bytes      = data.get("down_bytes", 0),
                    up_bytes_rate   = data.get("up_bytes_rate"),
                    down_bytes_rate = data.get("down_bytes_rate"),
                )
                sess.add(rec)
                sess.commit()
                return True
        except Exception as exc:
            logger.warning("Failed to insert network stat: {}", exc)
            return False

    def get_network_stats(self, network_name: str, hours: int = 24) -> pd.DataFrame:
        """Get historical network statistics."""
        since = datetime.utcnow() - timedelta(hours=hours)
        with self._session() as sess:
            rows = (
                sess.query(NetworkStat)
                .filter(
                    NetworkStat.network_name == network_name,
                    NetworkStat.timestamp >= since
                )
                .order_by(NetworkStat.timestamp.asc())
                .all()
            )
        
        if not rows:
            return pd.DataFrame()
        
        return pd.DataFrame([{
            "timestamp": r.timestamp,
            "num_clients": r.num_clients,
            "up_bytes": r.up_bytes,
            "down_bytes": r.down_bytes,
            "up_rate_bps": r.up_bytes_rate,
            "down_rate_bps": r.down_bytes_rate,
        } for r in rows])

    # ------------------------------------------------------------------
    # VPN Status
    # ------------------------------------------------------------------

    def insert_vpn_statuses(self, records: List[Dict[str, Any]], ts: datetime) -> None:
        with self._session() as sess:
            for r in records:
                sess.add(VPNStatus(
                    timestamp   = ts,
                    tunnel_name = r.get("tunnel_name"),
                    status      = r.get("status", "unknown"),
                    remote_ip   = r.get("remote_ip"),
                    uptime      = r.get("uptime"),
                ))
            sess.commit()

    def get_vpn_status(self) -> pd.DataFrame:
        """Latest snapshot of each VPN tunnel/session."""
        with self._session() as sess:
            subq = (
                sess.query(
                    VPNStatus.tunnel_name,
                    func.max(VPNStatus.timestamp).label("max_ts"),
                )
                .group_by(VPNStatus.tunnel_name)
                .subquery()
            )
            rows = (
                sess.query(VPNStatus)
                .join(
                    subq,
                    (VPNStatus.tunnel_name == subq.c.tunnel_name)
                    & (VPNStatus.timestamp == subq.c.max_ts),
                )
                .all()
            )
        if not rows:
            return pd.DataFrame()
        return pd.DataFrame([{
            "tunnel_name": r.tunnel_name,
            "status":      r.status,
            "remote_ip":   r.remote_ip,
            "uptime":      r.uptime,
            "timestamp":   r.timestamp,
        } for r in rows])

    def get_system_uptime(self) -> Optional[int]:
        """Returns the most recent device uptime in seconds."""
        with self._session() as sess:
            row = (
                sess.query(DeviceStat.uptime_sec)
                .order_by(DeviceStat.timestamp.desc())
                .first()
            )
        return row[0] if row else None

    def get_monthly_wan_bytes(self) -> Dict[str, int]:
        """
        Approximate monthly WAN data usage by summing WANStatus rx/tx bytes
        over the current calendar month. Since we store rate (B/s) × poll_interval,
        accumulate using the time delta between consecutive samples.
        Returns {"rx_bytes": N, "tx_bytes": N}.
        """
        now   = datetime.utcnow()
        start = datetime(now.year, now.month, 1)
        with self._session() as sess:
            rows = (
                sess.query(WANStatus.timestamp, WANStatus.rx_bytes, WANStatus.tx_bytes)
                .filter(
                    WANStatus.timestamp >= start,
                    WANStatus.interface == "WAN",
                )
                .order_by(WANStatus.timestamp.asc())
                .all()
            )
        if len(rows) < 2:
            return {"rx_bytes": 0, "tx_bytes": 0}

        total_rx = total_tx = 0
        for i in range(1, len(rows)):
            prev_ts, _, _ = rows[i - 1]
            curr_ts, rx, tx = rows[i]
            dt = (curr_ts - prev_ts).total_seconds()
            if dt <= 0 or dt > 600:  # skip gaps > 10 min
                continue
            total_rx += int((rx or 0) * dt)
            total_tx += int((tx or 0) * dt)
        return {"rx_bytes": total_rx, "tx_bytes": total_tx}
