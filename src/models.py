"""
SQLAlchemy ORM models — the authoritative schema for the database.

Versão 2 — suporta system-log do UniFi OS 3.x+ (firmware 8.x/9.x/10.x).
"""
from datetime import datetime
from sqlalchemy import (
    Column, Integer, String, Boolean, Float,
    DateTime, Text, BigInteger, Index,
)
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class Client(Base):
    """Known network devices — updated on every collection cycle."""
    __tablename__ = "clients"

    id                = Column(Integer, primary_key=True, autoincrement=True)
    mac               = Column(String(17), unique=True, nullable=False, index=True)
    name              = Column(String(255))          # user-defined alias in UniFi
    hostname          = Column(String(255))          # DHCP hostname
    ip                = Column(String(45))           # last-seen IP
    vendor            = Column(String(255))          # OUI vendor
    first_seen        = Column(DateTime, default=datetime.utcnow)
    last_seen         = Column(DateTime, default=datetime.utcnow)
    is_suspicious     = Column(Boolean, default=False)
    suspicious_reason = Column(Text)
    total_blocks      = Column(Integer, default=0)   # running total

    def display_name(self) -> str:
        return self.name or self.hostname or self.mac


class WANStatus(Base):
    """Point-in-time snapshot of each WAN interface."""
    __tablename__ = "wan_status"

    id         = Column(Integer, primary_key=True, autoincrement=True)
    timestamp  = Column(DateTime, default=datetime.utcnow, index=True)
    interface  = Column(String(10), nullable=False)   # WAN, WAN2
    status     = Column(String(10))                   # ok, error
    uptime     = Column(BigInteger)                   # seconds
    latency_ms = Column(Float)
    rx_bytes   = Column(BigInteger)
    tx_bytes   = Column(BigInteger)
    wan_ip     = Column(String(45))

    __table_args__ = (
        Index("ix_wan_interface_ts", "interface", "timestamp"),
    )


class FirewallBlock(Base):
    """
    Every firewall or traffic-rule block event, deduplicated by raw event ID.

    Suporta dois formatos de origem:
      - system_log : API v2 system-log/all  (firmware 8.x+ / UniFi OS 3.x+)
      - stat_event : API v1 /stat/event     (firmware legado)
    """
    __tablename__ = "firewall_blocks"

    id           = Column(Integer, primary_key=True, autoincrement=True)
    timestamp    = Column(DateTime, default=datetime.utcnow, index=True)
    raw_event_id = Column(String(128), unique=True, index=True)  # UUID ou ObjectID
    client_mac   = Column(String(17), index=True)
    client_ip    = Column(String(45))
    client_name  = Column(String(255))
    rule_name    = Column(String(255))
    rule_type    = Column(String(50))    # traffic_rule | firewall_rule
    destination  = Column(String(255))  # IP ou hostname de destino
    dst_port     = Column(Integer)
    protocol     = Column(String(10))   # tcp, udp, icmp
    category     = Column(String(100))  # YouTube, Social Media, …
    severity     = Column(String(20))   # low, medium, high, critical
    raw_message  = Column(Text)         # mensagem original completa (debug)
    source       = Column(String(20))   # system_log | stat_event

    __table_args__ = (
        Index("ix_fb_mac_ts", "client_mac", "timestamp"),
    )


class Threat(Base):
    """IPS/IDS and Threat Management events."""
    __tablename__ = "threats"

    id           = Column(Integer, primary_key=True, autoincrement=True)
    timestamp    = Column(DateTime, default=datetime.utcnow, index=True)
    raw_event_id = Column(String(128), unique=True, index=True)
    client_mac   = Column(String(17), index=True)
    client_ip    = Column(String(45))
    client_name  = Column(String(255))
    threat_type  = Column(String(100))
    severity     = Column(String(20))
    description  = Column(Text)
    action_taken = Column(String(50))


class DPITraffic(Base):
    """Per-client DPI traffic snapshot (accumulated bytes per category)."""
    __tablename__ = "dpi_traffic"

    id          = Column(Integer, primary_key=True, autoincrement=True)
    timestamp   = Column(DateTime, default=datetime.utcnow, index=True)
    client_mac  = Column(String(17), index=True)
    category    = Column(String(100))
    application = Column(String(100))
    rx_bytes    = Column(BigInteger, default=0)
    tx_bytes    = Column(BigInteger, default=0)


class VPNStatus(Base):
    """Point-in-time status for each configured VPN tunnel."""
    __tablename__ = "vpn_status"

    id          = Column(Integer, primary_key=True, autoincrement=True)
    timestamp   = Column(DateTime, default=datetime.utcnow, index=True)
    tunnel_name = Column(String(255))
    status      = Column(String(20))   # running, down
    remote_ip   = Column(String(45))
    uptime      = Column(BigInteger)   # seconds


class CollectionState(Base):
    """
    Persiste estado entre execuções do collector (chave-valor).

    Chaves usadas:
      last_syslog_ts_ms  — Unix epoch ms do evento mais recente coletado
                           via system-log. Usado para coleta incremental.
    """
    __tablename__ = "collection_state"

    key        = Column(String(64), primary_key=True)
    value      = Column(Text)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
