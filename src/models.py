"""
SQLAlchemy ORM models — the authoritative schema for the database.

Versão 3 — suporta system-log do UniFi OS 3.x+ (firmware 8.x/9.x/10.x)
           + device fingerprint, client snapshots, AP stats e rogue APs.
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
    # v3 — device fingerprint
    device_type       = Column(String(50))           # phone, computer, tablet, iot, gaming, tv, printer, camera, unknown
    os_name           = Column(String(100))          # iOS 17, Windows 11, Android 14
    dev_family        = Column(String(100))          # Apple iOS, Samsung Android

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


class ClientSnapshot(Base):
    """Point-in-time snapshot of each active client's radio/wired statistics."""
    __tablename__ = "client_snapshots"

    id            = Column(Integer, primary_key=True, autoincrement=True)
    timestamp     = Column(DateTime, default=datetime.utcnow, index=True)
    client_mac    = Column(String(17), index=True)
    signal        = Column(Integer)        # RSSI dBm (negativo, ex: -65)
    noise         = Column(Integer)        # noise floor dBm
    tx_rate       = Column(Float)          # Mbps negociados tx
    rx_rate       = Column(Float)          # Mbps negociados rx
    satisfaction  = Column(Integer)        # 0-100 score UniFi
    tx_bytes_rate = Column(BigInteger)     # bytes/s agora
    rx_bytes_rate = Column(BigInteger)     # bytes/s agora
    ap_mac        = Column(String(17))
    radio_band    = Column(String(10))     # "2.4GHz", "5GHz", "6GHz", "Wired"
    channel       = Column(Integer)
    essid         = Column(String(255))
    is_wired      = Column(Boolean, default=False)
    uptime_sec    = Column(BigInteger)

    __table_args__ = (
        Index("ix_cs_mac_ts", "client_mac", "timestamp"),
    )


class APStat(Base):
    """Point-in-time statistics for each Access Point / network device."""
    __tablename__ = "ap_stats"

    id              = Column(Integer, primary_key=True, autoincrement=True)
    timestamp       = Column(DateTime, default=datetime.utcnow, index=True)
    mac             = Column(String(17), index=True)
    name            = Column(String(255))
    model           = Column(String(100))
    ip              = Column(String(45))
    num_clients     = Column(Integer, default=0)
    num_clients_24g = Column(Integer, default=0)
    num_clients_5g  = Column(Integer, default=0)
    num_clients_6g  = Column(Integer, default=0)
    tx_bytes_rate   = Column(BigInteger)
    rx_bytes_rate   = Column(BigInteger)
    satisfaction    = Column(Integer)
    uptime_sec      = Column(BigInteger)
    channel_24g     = Column(Integer)
    channel_5g      = Column(Integer)

    __table_args__ = (
        Index("ix_ap_mac_ts", "mac", "timestamp"),
    )


class DeviceStat(Base):
    """Detailed hardware and radio statistics for UniFi devices (APs, Switches, Gateways)."""
    __tablename__ = "device_stats"

    id                      = Column(Integer, primary_key=True, autoincrement=True)
    timestamp               = Column(DateTime, default=datetime.utcnow, index=True)
    device_mac              = Column(String(17), index=True)  # MAC do dispositivo
    device_name             = Column(String(255))             # Nome do dispositivo
    device_model            = Column(String(100))             # Modelo (ex: UAP-AC-Pro)
    device_ip               = Column(String(45))              # IP do dispositivo
    cpu_utilization_pct     = Column(Float)                   # CPU em %
    memory_utilization_pct  = Column(Float)                   # Memória em %
    load_average_1min       = Column(Float)                   # Carga média 1 min
    load_average_5min       = Column(Float)                   # Carga média 5 min
    load_average_15min      = Column(Float)                   # Carga média 15 min
    uptime_sec              = Column(BigInteger)              # Uptime em segundos
    last_heartbeat_at       = Column(DateTime)                # Último heartbeat
    # Métricas por rádio (2.4GHz, 5GHz, 6GHz)
    tx_retries_pct_24g      = Column(Float)                   # TX retries % em 2.4GHz
    tx_retries_pct_5g       = Column(Float)                   # TX retries % em 5GHz
    tx_retries_pct_6g       = Column(Float)                   # TX retries % em 6GHz
    frequency_24g           = Column(Float)                   # Frequência 2.4GHz
    frequency_5g            = Column(Float)                   # Frequência 5GHz
    frequency_6g            = Column(Float)                   # Frequência 6GHz
    # Tráfego
    tx_rate_bps             = Column(BigInteger)              # TX rate em bps
    rx_rate_bps             = Column(BigInteger)              # RX rate em bps

    __table_args__ = (
        Index("ix_device_mac_ts", "device_mac", "timestamp"),
    )


class NetworkStat(Base):
    """Per-network traffic and client statistics."""
    __tablename__ = "network_stats"

    id              = Column(Integer, primary_key=True, autoincrement=True)
    timestamp       = Column(DateTime, default=datetime.utcnow, index=True)
    network_name    = Column(String(255), index=True)         # Nome da rede
    network_id      = Column(String(128))                     # ID da rede no UniFi
    ip_subnet       = Column(String(45))                      # Sub-rede IP
    num_clients     = Column(Integer, default=0)              # Número de clientes
    up_bytes        = Column(BigInteger, default=0)           # Upload total
    down_bytes      = Column(BigInteger, default=0)           # Download total
    up_bytes_rate   = Column(BigInteger)                      # Upload rate (bytes/s)
    down_bytes_rate = Column(BigInteger)                      # Download rate (bytes/s)

    __table_args__ = (
        Index("ix_network_name_ts", "network_name", "timestamp"),
    )


class RogueAP(Base):
    """Neighbouring / rogue access points detected by managed APs."""
    __tablename__ = "rogue_aps"

    id         = Column(Integer, primary_key=True, autoincrement=True)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen  = Column(DateTime, default=datetime.utcnow)
    bssid      = Column(String(17), unique=True, index=True)
    ssid       = Column(String(255))
    channel    = Column(Integer)
    signal     = Column(Integer)
    security   = Column(String(100))
    is_rogue   = Column(Boolean, default=True)
    ap_mac     = Column(String(17))   # MAC do AP que detectou
