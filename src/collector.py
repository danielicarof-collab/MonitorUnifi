"""
Data Collector — polls the UniFi API and persists everything to the database.

Pipeline por ciclo de coleta:
  1. Sync client registry (MAC → nome/hostname/IP/vendor).
  2. Snapshot WAN status (latência, uptime, bytes).
  3. Coleta eventos de segurança:
       → Primeiro tenta system-log v2 (firmware 8.x+ / UniFi OS 3.x+)
       → Fallback para /stat/event v1 (firmware legado)
  4. Snapshot DPI por cliente.
  5. AuditEngine (detecção de dispositivos suspeitos).

Coleta incremental: o system-log usa timestampFrom para buscar apenas
eventos novos desde a última execução. Na primeira execução importa
todo o histórico disponível (pode ser 12k+ eventos).
"""
from __future__ import annotations

import re
import signal
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import schedule
from loguru import logger

from src.api_client import UniFiAPIClient
from src.audit_engine import AuditEngine
from src.database_manager import DatabaseManager

# ── regex para parsear mensagem do system-log ─────────────────────────
# Formato: "DEVICE_NAME MAC_SUFFIX was blocked from accessing DST_IP[:PORT]
#           by the RULE_NAME [firewall|traffic] rule"
_BLOCK_RE = re.compile(
    r"(?P<device>.+?)\s+"
    r"(?P<mac_suffix>[0-9a-f]{2}(?::[0-9a-f]{2}){1,5})\s+"
    r"was blocked from accessing\s+"
    r"(?P<dst>[\d.a-fA-F:]+)"
    r"(?::(?P<port>\d+))?"
    r"\s+by\s+the\s+(?P<rule>.+?)(?:\s+(?:firewall|traffic)\s+rule)?\.?$",
    re.IGNORECASE,
)

# Mapeamento nível system-log → severidade interna
_LEVEL_TO_SEV: Dict[str, str] = {
    "error":    "high",
    "critical": "critical",
    "warn":     "medium",
    "warning":  "medium",
    "info":     "low",
    "debug":    "low",
}


class DataCollector:
    def __init__(
        self,
        api: UniFiAPIClient,
        db: DatabaseManager,
        audit: AuditEngine,
        events_fetch_limit: int = 3000,
    ) -> None:
        self._api    = api
        self._db     = db
        self._audit  = audit
        self._limit  = events_fetch_limit
        self._client_map: Dict[str, str] = {}   # mac → display name cache

    # ------------------------------------------------------------------
    # Entry points
    # ------------------------------------------------------------------

    def collect_once(self) -> None:
        """Executa um ciclo completo de coleta."""
        logger.info("▶ Collection cycle starting at {}", datetime.utcnow().isoformat())
        try:
            self._api.discover_site()
            self._sync_clients()
            self._collect_client_snapshots()
            self._collect_wan_status()
            self._collect_wan_throughput()
            self._collect_device_statistics()
            self._collect_port_stats()
            self._collect_network_statistics()
            self._collect_vpn_status()
            self._process_events()
            self._collect_dpi()
            self._collect_ap_stats()
            self._collect_rogue_aps()
            self._collect_firewall_rules()
            self._collect_port_forwards()
            self._audit.run()
        except Exception as exc:
            logger.exception("Unhandled error in collection cycle: {}", exc)
        logger.info("✔ Collection cycle complete")

    def run_continuous(self, interval_seconds: int = 60) -> None:
        """Executa continuamente até SIGINT/SIGTERM."""
        self.collect_once()
        schedule.every(interval_seconds).seconds.do(self.collect_once)
        logger.info(
            "Scheduler started — polling every {}s.  Ctrl+C to stop.",
            interval_seconds,
        )

        stop = {"flag": False}

        def _handle(signum, frame):  # noqa: ANN001
            logger.info("Shutdown signal — stopping collector.")
            stop["flag"] = True

        signal.signal(signal.SIGINT,  _handle)
        signal.signal(signal.SIGTERM, _handle)

        while not stop["flag"]:
            schedule.run_pending()
            time.sleep(1)

        self._api.logout()
        logger.info("Collector stopped cleanly.")

    # ------------------------------------------------------------------
    # Step 1: Sync client registry
    # ------------------------------------------------------------------

    def _sync_clients(self) -> None:
        clients = self._api.get_known_clients()
        active  = self._api.get_active_clients()

        merged: Dict[str, Dict] = {}
        for c in clients:
            mac = c.get("mac", "").lower()
            if mac:
                merged[mac] = c
        for c in active:
            mac = c.get("mac", "").lower()
            if mac:
                merged.setdefault(mac, {}).update(c)

        for mac, data in merged.items():
            # Enrich data with device fingerprint before upsert
            data["device_type"] = AuditEngine.infer_device_type(
                dev_cat  = data.get("dev_cat", ""),
                vendor   = data.get("oui", ""),
                hostname = data.get("hostname", ""),
                os_name  = data.get("os_name", ""),
            )
            data["os_name"]    = data.get("os_name") or data.get("os_class")
            data["dev_family"] = data.get("dev_family") or data.get("dev_cat")
            self._db.upsert_client(data)

        self._client_map = self._db.get_all_clients_map()
        logger.debug("Client registry synced: {} devices", len(merged))

    # ------------------------------------------------------------------
    # Step 2: WAN status snapshot
    # ------------------------------------------------------------------

    def _collect_wan_status(self) -> None:
        health_data = self._api.get_health()
        devices     = self._api.get_devices()
        ts = datetime.utcnow()

        # Build supplemental data from /stat/device wan1/wan2 fields
        device_wan: Dict[str, Dict] = {}
        for dev in devices:
            for iface_key, label in (("wan1", "WAN"), ("wan2", "WAN2")):
                wan_data = dev.get(iface_key)
                if isinstance(wan_data, dict) and wan_data:
                    device_wan[label] = wan_data

        saved_ifaces: set = set()

        # Primary source: health API subsystems
        for subsystem in health_data:
            sub = subsystem.get("subsystem", "").lower()
            if sub not in ("wan", "wan2"):
                continue

            label   = "WAN2" if sub == "wan2" else "WAN"
            dev_wan = device_wan.get(label, {})

            # uptime_stats: per-WAN link uptime (seconds) from health monitors
            uptime_stats_all = subsystem.get("uptime_stats") or {}
            wan_stat = uptime_stats_all.get(label) or {}
            wan_uptime = wan_stat.get("uptime")  # seconds this WAN link has been up

            # Latency: health latency_average from monitors, fallback to device data
            latency = (
                subsystem.get("latency")
                or wan_stat.get("latency_average")
                or dev_wan.get("latency")
                or dev_wan.get("latency_ms")
            )
            wan_ip = subsystem.get("wan_ip") or dev_wan.get("ip")

            self._db.insert_wan_status({
                "interface": label,
                "status":    subsystem.get("status", "unknown"),
                "uptime":    wan_uptime,
                "latency":   latency,
                "rx_bytes":  subsystem.get("rx_bytes-r"),
                "tx_bytes":  subsystem.get("tx_bytes-r"),
                "wan_ip":    wan_ip,
                "timestamp": ts,
            })
            saved_ifaces.add(label)

            # WAN2 não tem subsistema próprio no health (firmware 10.3.58) —
            # seus dados ficam em uptime_stats.WAN2 dentro do subsistema "wan"
            if sub == "wan" and "WAN2" not in saved_ifaces:
                wan2_stat = uptime_stats_all.get("WAN2") or {}
                wan2_upt  = wan2_stat.get("uptime")
                dev_wan2  = device_wan.get("WAN2", {})
                wan2_ip   = dev_wan2.get("ip")
                if wan2_upt or wan2_ip:
                    self._db.insert_wan_status({
                        "interface": "WAN2",
                        "status":    "ok" if wan2_upt else "unknown",
                        "uptime":    wan2_upt,
                        "latency":   (wan2_stat.get("latency_average")
                                      or dev_wan2.get("latency")),
                        "rx_bytes":  dev_wan2.get("rx_bytes-r"),
                        "tx_bytes":  dev_wan2.get("tx_bytes-r"),
                        "wan_ip":    wan2_ip,
                        "timestamp": ts,
                    })
                    saved_ifaces.add("WAN2")

        # Fallback: device wan1/wan2 data for any WAN the health API missed
        for label, dev_wan in device_wan.items():
            if label in saved_ifaces:
                continue
            wan_ip  = dev_wan.get("ip") or dev_wan.get("wan_ip")
            latency = dev_wan.get("latency") or dev_wan.get("latency_ms")
            avail   = dev_wan.get("availability", 0)
            if not wan_ip and latency is None:
                continue
            status = "ok" if (avail and float(avail) > 0) else "unknown"
            self._db.insert_wan_status({
                "interface": label,
                "status":    status,
                "uptime":    None,
                "latency":   latency,
                "rx_bytes":  dev_wan.get("rx_bytes-r"),
                "tx_bytes":  dev_wan.get("tx_bytes-r"),
                "wan_ip":    wan_ip,
                "timestamp": ts,
            })
            saved_ifaces.add(label)
            logger.debug("WAN {} coletado via device data (health API não retornou)", label)

        logger.debug("WAN status snapshot salvo: {}", saved_ifaces)

    # ------------------------------------------------------------------
    # Step 3: Security events — system-log v2 com fallback para v1
    # ------------------------------------------------------------------

    def _process_events(self) -> None:
        """
        Tenta coletar eventos de segurança via system-log (v2).
        Se o endpoint não existir (firmware antigo), usa /stat/event (v1).
        """
        new_blocks = 0

        # ── Tentativa principal: system-log v2 ────────────────────────
        syslog_blocks = self._collect_from_system_log()
        if syslog_blocks is not None:
            new_blocks = syslog_blocks
        else:
            # ── Fallback: /stat/event v1 + /stat/alarm ────────────────
            new_blocks, new_threats = self._collect_from_stat_event()
            logger.info(
                "Events processed (v1) — {} new blocks, {} new threats",
                new_blocks, new_threats,
            )
            return

        logger.info(
            "Events processed (system-log) — {} new firewall blocks", new_blocks
        )

    def _collect_from_system_log(self) -> Optional[int]:
        """
        Coleta eventos do system-log v2 com paginação por cursor de timestamp.

        O servidor ignora pageNum/offset — sempre retorna os eventos mais recentes.
        Paginamos recuando o cursor timestampTo: a cada página usamos o timestamp
        do evento mais antigo como limite superior da próxima requisição.

        Retorna o número de novos registros inseridos,
        ou None se o endpoint não estiver disponível (firmware antigo).
        """
        last_ts_raw  = self._db.get_last_event_timestamp()  # bruto (s ou ms)
        is_first_run = last_ts_raw is None

        # Margem retroativa: 5 s ou 5 000 ms para não perder eventos no limite
        if last_ts_raw is not None:
            margin  = 5_000 if last_ts_raw > 1_000_000_000_000 else 5
            ts_from = last_ts_raw - margin
        else:
            ts_from = None

        page_size     = 500
        total_new     = 0
        newest_ts_raw = last_ts_raw or 0
        cursor_ts_to: Optional[int] = None  # None = sem limite (mais recentes)
        page_count    = 0
        MAX_PAGES     = 300                  # 300 × 500 = 150 000 eventos máx.

        if is_first_run:
            logger.info("Primeira coleta via system-log — importando histórico completo…")

        while page_count < MAX_PAGES:
            events, raw_total = self._api.get_system_log(
                categories=["SECURITY"],
                page_size=page_size,
                page_num=1,          # mantemos por compatibilidade; servidor ignora
                ts_from=ts_from,
                ts_to=cursor_ts_to,
            )

            # Primeira página vazia = endpoint inexistente → sinaliza fallback v1
            if page_count == 0 and not events:
                return None

            if page_count == 0 and events:
                logger.debug("system-log — chaves do evento: {}", list(events[0].keys()))
                if is_first_run:
                    logger.info(
                        "system-log — {} eventos disponíveis. "
                        "Importando em páginas de {} eventos…",
                        raw_total, page_size,
                    )

            if not events:
                break  # sem mais eventos neste intervalo

            # ── Processa página ──────────────────────────────────────────
            oldest_raw_in_page: Optional[int] = None
            parsed_batch: List[Dict[str, Any]] = []

            for event in events:
                parsed = self._parse_syslog_block(event)
                if parsed:
                    parsed_batch.append(parsed)

                raw_ts = self._extract_raw_ts(event)
                if raw_ts:
                    if raw_ts > newest_ts_raw:
                        newest_ts_raw = raw_ts
                    if oldest_raw_in_page is None or raw_ts < oldest_raw_in_page:
                        oldest_raw_in_page = raw_ts

            new_in_page = self._db.batch_insert_firewall_blocks(parsed_batch)
            total_new  += new_in_page
            page_count += 1

            logger.info(
                "system-log página {} — {} eventos, {} novos (acumulado: {})",
                page_count, len(events), new_in_page, total_new,
            )

            # Página incompleta = última disponível neste intervalo → encerra
            if len(events) < page_size:
                break

            # Avança cursor para antes do evento mais antigo desta página
            if oldest_raw_in_page is not None:
                cursor_ts_to = oldest_raw_in_page - 1
            else:
                break

        # Persiste cursor para a próxima coleta incremental
        if newest_ts_raw > (last_ts_raw or 0):
            self._db.set_last_event_timestamp(newest_ts_raw)

        return total_new

    def _extract_raw_ts(self, event: Dict[str, Any]) -> Optional[int]:
        """
        Retorna o timestamp BRUTO do evento como inteiro, sem converter entre
        segundos e milissegundos — preserva o formato nativo do servidor para
        uso direto como cursor de paginação (timestampTo).
        """
        for key in ("timestamp", "time", "ts"):
            v = event.get(key)
            if isinstance(v, (int, float)) and v > 0:
                return int(v)
        # Fallback: ISO 8601 → segundos Unix
        for key in ("datetime", "created_at", "date"):
            v = event.get(key)
            if isinstance(v, str) and v:
                try:
                    dt = datetime.fromisoformat(v.replace("Z", "+00:00"))
                    return int(dt.timestamp())
                except ValueError:
                    pass
        return None

    def _raw_ts_to_datetime(self, raw_ts: int) -> datetime:
        """
        Converte timestamp bruto (segundos ou milissegundos) para datetime UTC.
        Auto-detecta: > 10^12 → ms; caso contrário → segundos.
        """
        if raw_ts > 1_000_000_000_000:
            return datetime.fromtimestamp(raw_ts / 1000, tz=timezone.utc).replace(tzinfo=None)
        return datetime.fromtimestamp(raw_ts, tz=timezone.utc).replace(tzinfo=None)

    def _extract_event_ts_ms(self, event: Dict[str, Any]) -> Optional[int]:
        """Legado — mantido para compatibilidade. Use _extract_raw_ts() + _raw_ts_to_datetime()."""
        raw = self._extract_raw_ts(event)
        if raw is None:
            return None
        # Normaliza para ms
        return raw if raw > 1_000_000_000_000 else raw * 1000

    def _parse_syslog_block(
        self, event: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """
        Converte um evento do system-log v2 no formato interno de FirewallBlock.

        Estrutura real (UniFi OS 5.x / Network 9+):
          - message_raw  : template com variáveis "{CHAVE_MAIÚSCULA}"
          - parameters   : dict onde cada chave é uma variável do template,
                           e cada valor é {"id": "...", "name": "..."}
              SRC_CLIENT → {"id": "MAC", "ip": "10.x.x.x", "name": "Dispositivo"}
              DST_IP     → {"id": "95.100.93.235", "name": "95.100.93.235"}
              TRIGGER    → {"id": "uuid", "name": "Block Stream"}
          - target       : NOME de uma chave em parameters (ex: "TRIGGER"), NÃO um IP
          - severity     : "MEDIUM" / "HIGH" / "LOW" / "CRITICAL"  (maiúsculo)
          - type         : "CONTENT_FILTERING_AND_RESTRICTIONS" → categoria
        """
        # ── ID de deduplicação ────────────────────────────────────────
        raw_id = (
            event.get("id")
            or event.get("_id")
            or event.get("uuid")
            or event.get("eventId")
        )
        if not raw_id:
            return None

        # ── Timestamp ─────────────────────────────────────────────────
        raw_ts = self._extract_raw_ts(event)
        ts = self._raw_ts_to_datetime(raw_ts) if raw_ts else datetime.utcnow()

        # ── Template de mensagem (não preenchido ainda) ───────────────
        message_template = (
            event.get("message_raw")
            or event.get("message")
            or event.get("msg")
            or event.get("title_raw")
            or ""
        )

        # ── Severidade (system-log v2 usa maiúsculo) ──────────────────
        raw_sev = str(event.get("severity") or event.get("level") or "MEDIUM").upper()
        _SEV_MAP = {
            "LOW": "low", "MEDIUM": "medium", "HIGH": "high", "CRITICAL": "critical",
            "INFO": "low", "WARN": "medium", "WARNING": "medium", "ERROR": "high",
        }
        severity = _SEV_MAP.get(raw_sev, "medium")

        # ── Parameters: dict de template-variables UPPERCASE ──────────
        # Cada valor é {"id": "identificador", "name": "nome legível", ...}
        params: Dict[str, Any] = event.get("parameters") or {}

        # Fonte — SRC_CLIENT: id=MAC, ip=IP, name=nome do dispositivo
        src_client = params.get("SRC_CLIENT") or {}
        if isinstance(src_client, dict):
            src_ip: Optional[str] = src_client.get("ip") or src_client.get("ipAddr")
            _mac_id = str(src_client.get("id") or "")
            src_mac_raw: Optional[str] = _mac_id if ":" in _mac_id else None
            param_client_name: Optional[str] = (
                src_client.get("name") or src_client.get("hostname")
            )
        else:
            src_ip = None
            src_mac_raw = None
            param_client_name = None

        # Destino — DST_IP: id=endereço IP de destino
        dst_ip: Optional[str] = None
        for _dst_key in ("DST_IP", "DESTINATION", "DEST_IP", "TARGET_IP", "DST"):
            _dst_obj = params.get(_dst_key)
            if isinstance(_dst_obj, dict):
                _ip_val = _dst_obj.get("id") or _dst_obj.get("name")
                if _ip_val:
                    dst_ip = str(_ip_val)
                    break

        # Porta de destino — DST_PORT
        dst_port_raw: Optional[Any] = None
        for _port_key in ("DST_PORT", "DESTINATION_PORT", "PORT"):
            _port_obj = params.get(_port_key)
            if _port_obj:
                dst_port_raw = (
                    _port_obj.get("id") if isinstance(_port_obj, dict) else _port_obj
                )
                break

        # Regra / política — TRIGGER: name=nome da regra que disparou o bloqueio
        rule_name: Optional[str] = None
        for _rule_key in ("TRIGGER", "RULE", "POLICY", "FIREWALL_RULE",
                          "CONTENT_FILTER", "ACCESS_CONTROL"):
            _rule_obj = params.get(_rule_key)
            if isinstance(_rule_obj, dict) and _rule_obj.get("name"):
                rule_name = _rule_obj["name"]
                break

        # Protocolo — PROTOCOL
        protocol: Optional[Any] = None
        _proto_obj = params.get("PROTOCOL") or params.get("IP_PROTOCOL")
        if _proto_obj:
            protocol = (
                _proto_obj.get("name") if isinstance(_proto_obj, dict) else str(_proto_obj)
            )

        # ── Preenche template com valores reais dos parameters ────────
        # "{SRC_CLIENT} was blocked..." → "Galaxy-A14-5G was blocked..."
        message = message_template
        for _pkey, _pval in params.items():
            _display = (
                (_pval.get("name") or _pval.get("id") or _pkey)
                if isinstance(_pval, dict)
                else str(_pval)
            )
            message = message.replace("{" + _pkey + "}", str(_display))

        # ── Fallback: campos camelCase no nível raiz (firmware antigo) ──
        if not src_ip:
            src_ip = (
                event.get("srcIp") or event.get("src_ip")
                or event.get("sourceIp") or event.get("clientIp")
            )
        if not src_mac_raw:
            src_mac_raw = (
                event.get("srcMac") or event.get("src_mac")
                or event.get("sourceMac") or event.get("deviceMac")
            )
            _src_field = event.get("source")
            if isinstance(_src_field, dict):
                src_ip      = src_ip      or _src_field.get("ip")
                src_mac_raw = src_mac_raw or _src_field.get("mac")
        if not dst_ip:
            dst_ip = (
                event.get("dstIp") or event.get("dst_ip")
                or event.get("destinationIp")
            )
            _dst_field = event.get("destination")
            if isinstance(_dst_field, dict):
                dst_ip = dst_ip or _dst_field.get("ip")
        if not rule_name:
            rule_name = (
                event.get("ruleName") or event.get("rule_name")
                or event.get("policy")
            )
        if not protocol:
            protocol = (
                event.get("protocol") or event.get("proto")
                or event.get("ipProtocol")
            )
        if isinstance(protocol, int):
            protocol = {6: "tcp", 17: "udp", 1: "icmp"}.get(protocol, str(protocol))

        # ── Normalização ──────────────────────────────────────────────
        src_mac  = src_mac_raw.lower() if isinstance(src_mac_raw, str) else None
        dst_port = int(dst_port_raw) if dst_port_raw else None

        # ── Nome do cliente ───────────────────────────────────────────
        # Prefere nome do parameters["SRC_CLIENT"]["name"] sobre lookup de MAC
        client_name = param_client_name or self._resolve_client_name(src_mac, src_ip)

        # ── Tipo de regra e categoria ─────────────────────────────────
        rule_type = AuditEngine.classify_rule_type_syslog(event, rule_name or "")
        category  = AuditEngine.extract_category_syslog(event, rule_name or "", message)

        return {
            "raw_event_id": str(raw_id),
            "timestamp":    ts,
            "client_mac":   src_mac,
            "client_ip":    src_ip,
            "client_name":  client_name,
            "rule_name":    rule_name,
            "rule_type":    rule_type,
            "destination":  dst_ip,
            "dst_port":     dst_port,
            "protocol":     str(protocol).lower() if protocol else None,
            "category":     category,
            "severity":     severity,
            "raw_message":  message[:500] if message else None,
            "source":       "system_log",
        }

    # ------------------------------------------------------------------
    # Fallback: coleta via /stat/event v1 (firmware legado)
    # ------------------------------------------------------------------

    def _collect_from_stat_event(self) -> Tuple[int, int]:
        """Coleta via /stat/event e /stat/alarm (firmware ≤ 7.x)."""
        events = self._api.get_events(limit=self._limit)
        alarms = self._api.get_alarms()

        new_blocks  = 0
        new_threats = 0

        for event in events:
            key = event.get("key", "")
            if UniFiAPIClient.is_block_event(key):
                if self._persist_block_v1(event):
                    new_blocks += 1
            elif UniFiAPIClient.is_threat_event(key):
                if self._persist_threat_v1(event):
                    new_threats += 1

        for alarm in alarms:
            if self._persist_threat_v1(alarm, from_alarm=True):
                new_threats += 1

        return new_blocks, new_threats

    def _persist_block_v1(self, event: Dict[str, Any]) -> bool:
        raw_id = event.get("_id")
        if not raw_id:
            return False

        mac  = (event.get("src_mac") or event.get("client_mac") or "").lower() or None
        ip   = event.get("src") or event.get("client_ip")
        name = self._resolve_client_name(mac, ip)

        return self._db.insert_firewall_block({
            "raw_event_id": raw_id,
            "timestamp":    self._parse_timestamp(event),
            "client_mac":   mac,
            "client_ip":    ip,
            "client_name":  name,
            "rule_name":    event.get("rule_name") or event.get("name"),
            "rule_type":    AuditEngine.classify_rule_type(event),
            "destination":  event.get("dst") or event.get("dest_ip"),
            "dst_port":     event.get("dst_port") or event.get("dstport"),
            "protocol":     self._proto_str(event.get("proto")),
            "category":     AuditEngine.extract_category(event),
            "severity":     AuditEngine.extract_severity(event),
            "raw_message":  event.get("msg", "")[:500] if event.get("msg") else None,
            "source":       "stat_event",
        })

    def _persist_threat_v1(
        self, event: Dict[str, Any], from_alarm: bool = False
    ) -> bool:
        raw_id = event.get("_id")
        if not raw_id:
            return False

        mac  = (event.get("src_mac") or event.get("client_mac") or "").lower() or None
        ip   = event.get("src") or event.get("client_ip")
        name = self._resolve_client_name(mac, ip)

        return self._db.insert_threat({
            "raw_event_id": raw_id,
            "timestamp":    self._parse_timestamp(event),
            "client_mac":   mac,
            "client_ip":    ip,
            "client_name":  name,
            "threat_type":  event.get("threat_type") or event.get("key") or "IPS",
            "severity":     AuditEngine.extract_severity(event),
            "description":  event.get("msg") or event.get("message"),
            "action_taken": event.get("action") or event.get("action_taken"),
        })

    # ------------------------------------------------------------------
    # Step 2b: Client snapshots (radio/wired stats per active client)
    # ------------------------------------------------------------------

    def _collect_client_snapshots(self) -> None:
        active = self._api.get_active_clients()
        records = []
        _RADIO_MAP = {"ng": "2.4 GHz", "na": "5 GHz", "6e": "6 GHz"}
        for c in active:
            mac = (c.get("mac") or "").lower()
            if not mac:
                continue
            is_wired = bool(c.get("is_wired", False))
            radio_raw = c.get("radio", "")
            radio_band = "Wired" if is_wired else _RADIO_MAP.get(radio_raw, radio_raw or "Wi-Fi")
            tx_rate_kbps = c.get("tx_rate")
            rx_rate_kbps = c.get("rx_rate")
            records.append({
                "client_mac":    mac,
                "signal":        c.get("signal"),
                "noise":         c.get("noise"),
                "tx_rate":       (tx_rate_kbps / 1000) if tx_rate_kbps else None,
                "rx_rate":       (rx_rate_kbps / 1000) if rx_rate_kbps else None,
                "satisfaction":  c.get("satisfaction"),
                "tx_bytes_rate": c.get("tx_bytes-r"),
                "rx_bytes_rate": c.get("rx_bytes-r"),
                "ap_mac":        (c.get("ap_mac") or "").lower() or None,
                "radio_band":    radio_band,
                "channel":       c.get("channel"),
                "essid":         c.get("essid"),
                "is_wired":      is_wired,
                "uptime_sec":    c.get("uptime"),
            })
        if records:
            self._db.insert_client_snapshots(records)
            logger.debug("Client snapshots saved: {} entries", len(records))

    # ------------------------------------------------------------------
    # Step 5b: AP stats snapshot
    # ------------------------------------------------------------------

    def _collect_ap_stats(self) -> None:
        devices = self._api.get_devices()
        ts = datetime.utcnow()
        count = 0
        for dev in devices:
            mac = (dev.get("mac") or "").lower()
            if not mac:
                continue
            radio_stats = dev.get("radio_table_stats") or dev.get("radio_table") or []
            clients_24g = clients_5g = clients_6g = 0
            channel_24g = channel_5g = None
            for radio in radio_stats:
                name = radio.get("name", "")
                n_sta = radio.get("num_sta") or radio.get("user-num_sta", 0)
                ch = radio.get("channel")
                if name == "ng":
                    clients_24g = n_sta
                    channel_24g = ch
                elif name == "na":
                    clients_5g = n_sta
                    channel_5g = ch
                elif name in ("6e", "6g"):
                    clients_6g = n_sta
            self._db.insert_ap_stat({
                "timestamp":       ts,
                "mac":             mac,
                "name":            dev.get("name") or dev.get("hostname"),
                "model":           dev.get("model"),
                "ip":              dev.get("ip"),
                "num_clients":     dev.get("num_sta", 0),
                "num_clients_24g": clients_24g,
                "num_clients_5g":  clients_5g,
                "num_clients_6g":  clients_6g,
                "tx_bytes_rate":   dev.get("tx_bytes-r"),
                "rx_bytes_rate":   dev.get("rx_bytes-r"),
                "satisfaction":    dev.get("satisfaction"),
                "uptime_sec":      dev.get("uptime"),
                "channel_24g":     channel_24g,
                "channel_5g":      channel_5g,
            })
            count += 1
        logger.debug("AP stats saved: {} devices", count)

    # ------------------------------------------------------------------
    # Step 5c: Rogue AP scan
    # ------------------------------------------------------------------

    def _collect_rogue_aps(self) -> None:
        rogue_list = self._api.get_rogue_aps()
        for r in rogue_list:
            bssid = (r.get("bssid") or r.get("mac") or "").lower()
            if not bssid:
                continue
            self._db.upsert_rogue_ap({
                "bssid":    bssid,
                "ssid":     r.get("ssid"),
                "channel":  r.get("channel"),
                "signal":   r.get("rssi") or r.get("signal"),
                "security": r.get("security") or r.get("security_proto"),
                "is_rogue": r.get("is_rogue", False),
                "ap_mac":   (r.get("ap_mac") or "").lower() or None,
            })
        if rogue_list:
            logger.debug("Rogue APs updated: {} entries", len(rogue_list))

    # ------------------------------------------------------------------
    # Step 4: DPI traffic snapshot
    # ------------------------------------------------------------------

    def _collect_dpi(self) -> None:
        dpi_data = self._api.get_dpi_stats()
        records: List[Dict] = []

        for client_dpi in dpi_data:
            mac = (client_dpi.get("mac") or "").lower()
            if not mac:
                continue

            for cat_entry in client_dpi.get("by_cat", []):
                cat_id = cat_entry.get("cat", 0)
                records.append({
                    "client_mac":  mac,
                    "category":    UniFiAPIClient.dpi_category_name(cat_id),
                    "application": "",
                    "rx_bytes":    cat_entry.get("rx_bytes", 0),
                    "tx_bytes":    cat_entry.get("tx_bytes", 0),
                })

            for app_entry in client_dpi.get("by_app", []):
                cat_id = app_entry.get("cat", 0)
                records.append({
                    "client_mac":  mac,
                    "category":    UniFiAPIClient.dpi_category_name(cat_id),
                    "application": app_entry.get("app", ""),
                    "rx_bytes":    app_entry.get("rx_bytes", 0),
                    "tx_bytes":    app_entry.get("tx_bytes", 0),
                })

        if records:
            self._db.insert_dpi_snapshot(records)
            logger.debug("DPI snapshot saved: {} entries", len(records))

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    def _resolve_client_name(
        self, mac: Optional[str], ip: Optional[str]
    ) -> Optional[str]:
        if mac:
            return self._client_map.get(mac.lower())
        return None

    def _parse_timestamp(self, event: Dict[str, Any]) -> datetime:
        raw = event.get("datetime") or event.get("time")
        if not raw:
            return datetime.utcnow()
        try:
            if isinstance(raw, (int, float)):
                return datetime.fromtimestamp(raw, tz=timezone.utc).replace(tzinfo=None)
            dt = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
            return dt.astimezone(timezone.utc).replace(tzinfo=None)
        except (ValueError, OSError):
            return datetime.utcnow()

    @staticmethod
    def _proto_str(proto: Any) -> Optional[str]:
        mapping = {"6": "tcp", "17": "udp", "1": "icmp"}
        if proto is None:
            return None
        return mapping.get(str(proto), str(proto))

    # ------------------------------------------------------------------
    # Device statistics — CPU, memory, temperature, speedtest
    # Reads from /stat/device (legacy API — no API Key needed)
    # ------------------------------------------------------------------

    def _collect_device_statistics(self) -> None:
        """
        Coleta CPU, memória, temperatura e uptime de todos os dispositivos UniFi
        a partir do endpoint legado /stat/device.

        Campos extraídos do JSON:
          sys_stats.cpu        → cpu_utilization_pct
          sys_stats.mem        → memory_utilization_pct
          temperatures[]       → temp_cpu, temp_board, temp_phy
          uplink.xput_down     → speedtest download (Mbps)
          uplink.xput_up       → speedtest upload  (Mbps)
          uplink.speedtest_ping→ speedtest ping    (ms)
        """
        devices = self._api.get_devices()
        if not devices:
            logger.debug("Nenhum dispositivo disponível para coleta de estatísticas")
            return

        ts = datetime.utcnow()
        speedtest_records: List[Dict] = []

        for dev in devices:
            mac = (dev.get("mac") or "").lower()
            if not mac:
                continue

            # ── CPU / memória ────────────────────────────────────────────
            # UniFi Network API uses "system-stats" (with hyphen) as the key
            sys_stats = dev.get("system-stats") or dev.get("sys_stats") or {}
            cpu_pct = None
            mem_pct = None
            try:
                raw_cpu = sys_stats.get("cpu")
                raw_mem = sys_stats.get("mem")
                if raw_cpu is not None:
                    cpu_pct = float(raw_cpu)
                if raw_mem is not None:
                    mem_pct = float(raw_mem)
            except (TypeError, ValueError):
                pass

            # ── Temperatura ──────────────────────────────────────────────
            temp_cpu = temp_board = temp_phy = None
            for t in dev.get("temperatures") or []:
                t_type = str(t.get("type", "")).lower()
                t_val  = t.get("value")
                if t_val is None:
                    continue
                try:
                    t_val = float(t_val)
                except (TypeError, ValueError):
                    continue
                if t_type == "cpu":
                    temp_cpu = t_val
                elif t_type == "board":
                    # UniFi names: "Local" and "PHY" are both board-type
                    t_name = str(t.get("name", "")).lower()
                    if "phy" in t_name:
                        temp_phy = t_val
                    else:
                        temp_board = t_val

            # ── Rádio: TX retries por banda ──────────────────────────────
            tx_retries_24g = tx_retries_5g = tx_retries_6g = None
            freq_24g = freq_5g = freq_6g = None
            for radio in dev.get("radio_table_stats") or []:
                name = radio.get("name", "")
                # tx_retries is a running counter; use satisfaction as quality proxy
                retries = radio.get("tx_retries")
                tx_pkts = radio.get("tx_packets") or radio.get("tx_pkts")
                if retries and tx_pkts and tx_pkts > 0:
                    pct = round(retries / tx_pkts * 100, 2)
                else:
                    pct = None
                freq = radio.get("current_freq") or radio.get("freq")
                try:
                    freq = float(freq) / 1000 if freq and float(freq) > 1000 else (float(freq) if freq else None)
                except (TypeError, ValueError):
                    freq = None
                if name == "ng":
                    tx_retries_24g, freq_24g = pct, freq
                elif name == "na":
                    tx_retries_5g, freq_5g = pct, freq
                elif name in ("6e", "6g"):
                    tx_retries_6g, freq_6g = pct, freq

            # ── Speedtest (embedded in uplink) ───────────────────────────
            uplink = dev.get("uplink") or {}
            sp_down = uplink.get("xput_down")   # Mbps float
            sp_up   = uplink.get("xput_up")     # Mbps float
            sp_ping = uplink.get("speedtest_ping") or uplink.get("latency")
            if sp_down or sp_up:
                speedtest_records.append({
                    "interface":     "WAN",
                    "ping_ms":       float(sp_ping) if sp_ping else None,
                    "download_mbps": float(sp_down) if sp_down else None,
                    "upload_mbps":   float(sp_up)   if sp_up   else None,
                    "wan_ip":        uplink.get("ip") or dev.get("wan1", {}).get("ip"),
                    "timestamp":     ts,
                })

            self._db.insert_device_stat({
                "device_mac":            mac,
                "device_name":           dev.get("name") or dev.get("hostname"),
                "device_model":          dev.get("model"),
                "device_ip":             dev.get("ip"),
                "cpu_utilization_pct":   cpu_pct,
                "memory_utilization_pct": mem_pct,
                "load_average_1min":     None,  # not available from legacy API
                "load_average_5min":     None,
                "load_average_15min":    None,
                "uptime_sec":            dev.get("uptime"),
                "last_heartbeat_at":     None,
                "temp_cpu":              temp_cpu,
                "temp_board":            temp_board,
                "temp_phy":              temp_phy,
                "tx_retries_pct_24g":    tx_retries_24g,
                "tx_retries_pct_5g":     tx_retries_5g,
                "tx_retries_pct_6g":     tx_retries_6g,
                "frequency_24g":         freq_24g,
                "frequency_5g":          freq_5g,
                "frequency_6g":          freq_6g,
                "tx_rate_bps":           dev.get("tx_bytes-r"),
                "rx_rate_bps":           dev.get("rx_bytes-r"),
                "timestamp":             ts,
            })

        logger.debug("Device statistics snapshot saved for {} devices", len(devices))

        # Persist speedtest only when new values differ from last known result
        if speedtest_records:
            last = self._db.get_latest_speedtest()
            latest = speedtest_records[0]
            if (
                last is None
                or last.get("download_mbps") != latest.get("download_mbps")
                or last.get("upload_mbps")   != latest.get("upload_mbps")
            ):
                self._db.insert_speedtest_result(latest)
                logger.info(
                    "Speedtest result: ↓{:.1f} Mbps  ↑{:.1f} Mbps  ping {:.0f} ms",
                    latest.get("download_mbps") or 0,
                    latest.get("upload_mbps")   or 0,
                    latest.get("ping_ms")        or 0,
                )

    # ------------------------------------------------------------------
    # Port statistics — per-port rx/tx bytes, errors, drops
    # ------------------------------------------------------------------

    def _collect_port_stats(self) -> None:
        """
        Coleta estatísticas por porta de todos os dispositivos UniFi
        (switches, gateways) a partir do campo port_table em /stat/device.
        """
        devices = self._api.get_devices()
        if not devices:
            return

        for dev in devices:
            mac = (dev.get("mac") or "").lower()
            if not mac:
                continue
            port_table = dev.get("port_table") or []
            if not port_table:
                continue

            records: List[Dict] = []
            for port in port_table:
                port_idx = port.get("port_idx") or port.get("ifindex")
                if port_idx is None:
                    continue

                # PoE power: may be in mW or W depending on firmware
                poe_raw = port.get("poe_power")
                poe_w: Optional[float] = None
                if poe_raw is not None:
                    try:
                        poe_w = float(poe_raw)
                        if poe_w > 500:   # likely in mW
                            poe_w /= 1000
                    except (TypeError, ValueError):
                        pass

                records.append({
                    "device_mac":   mac,
                    "port_idx":     int(port_idx),
                    "port_name":    port.get("name") or port.get("ifname"),
                    "speed":        port.get("speed"),
                    "is_up":        bool(port.get("up", False)),
                    "rx_bytes":     port.get("rx_bytes"),
                    "tx_bytes":     port.get("tx_bytes"),
                    "rx_bytes_rate": port.get("rx_bytes-r"),
                    "tx_bytes_rate": port.get("tx_bytes-r"),
                    "rx_errors":    port.get("rx_errors"),
                    "tx_errors":    port.get("tx_errors"),
                    "rx_dropped":   port.get("rx_dropped"),
                    "tx_dropped":   port.get("tx_dropped"),
                    "rx_multicast": port.get("rx_multicast"),
                    "poe_power_w":  poe_w,
                })

            if records:
                self._db.insert_port_stats(records)

        logger.debug("Port stats collected for {} devices", len(devices))

    # ------------------------------------------------------------------
    # Network statistics — per-VLAN client count and traffic
    # ------------------------------------------------------------------

    def _collect_network_statistics(self) -> None:
        """
        Coleta estatísticas de tráfego e clientes para todas as redes configuradas.
        Usa Integrations API se disponível; cai para /rest/networkconf (legado, sem tráfego).
        """
        networks = self._api.get_networks()
        if not networks:
            logger.debug("Nenhuma rede disponível")
            return

        ts = datetime.utcnow()
        for network in networks:
            network_name = network.get("name")
            if not network_name:
                continue

            self._db.insert_network_stat({
                "network_name":   network_name,
                "network_id":     network.get("_id") or network.get("id"),
                "ip_subnet":      network.get("ip_subnet") or network.get("networkconf"),
                "num_clients":    network.get("num_clients", 0),
                "up_bytes":       network.get("up_bytes", 0),
                "down_bytes":     network.get("down_bytes", 0),
                "up_bytes_rate":  network.get("up_bytes_rate"),
                "down_bytes_rate": network.get("down_bytes_rate"),
                "timestamp":      ts,
            })

        logger.debug("Network statistics snapshot saved for {} networks", len(networks))

    # ------------------------------------------------------------------
    # WAN Throughput History (/stat/report/hourly.gw)
    # ------------------------------------------------------------------

    def _collect_wan_throughput(self) -> None:
        """
        Coleta histórico de throughput WAN via /stat/report/hourly.gw.

        Busca desde o início do mês atual para acumular dados precisos de
        uso mensal. A deduplicação no DB garante que buckets repetidos sejam
        ignorados. Também coleta o bucket mensal (/stat/report/monthly.gw)
        para exibição rápida de totais mensais.
        """
        import time as _time

        now_utc   = datetime.utcnow()
        end_ms    = int(_time.time() * 1000)
        # Início do mês atual em UTC (ms)
        month_start = datetime(now_utc.year, now_utc.month, 1)
        start_ms  = int(month_start.timestamp()) * 1000

        def _parse_buckets(raw_list: List[Dict], interval: str) -> None:
            records: List[Dict] = []
            for b in (raw_list or []):
                raw_ts = b.get("time") or b.get("timestamp")
                if raw_ts is None:
                    continue
                try:
                    ts_sec = int(raw_ts)
                    if ts_sec > 1_000_000_000_000:
                        ts_sec = ts_sec // 1000
                    ts = datetime.utcfromtimestamp(ts_sec)
                except (TypeError, ValueError):
                    continue
                records.append({
                    "timestamp":  ts,
                    "rx_bytes":   int(b.get("wan-rx_bytes") or b.get("rx_bytes") or 0),
                    "tx_bytes":   int(b.get("wan-tx_bytes") or b.get("tx_bytes") or 0),
                    "rx_dropped": int(b.get("wan-rx_dropped") or 0),
                    "tx_dropped": int(b.get("wan-tx_dropped") or 0),
                })
            if records:
                inserted = self._db.insert_wan_throughput(records, interval=interval)
                logger.info("WAN throughput [{}]: {} buckets, {} novos", interval, len(records), inserted)

        # Hourly: mês inteiro (deduplicação ignora os que já existem)
        hourly = self._api.get_gateway_report("hourly", start_ts=start_ms, end_ts=end_ms)
        if not hourly:
            logger.debug("WAN throughput: /stat/report/hourly.gw sem dados")
        else:
            _parse_buckets(hourly, "hourly")

        # Monthly: bucket único do mês corrente (para totais rápidos)
        monthly = self._api.get_gateway_report("monthly", start_ts=start_ms, end_ts=end_ms)
        _parse_buckets(monthly, "monthly")

    # ------------------------------------------------------------------
    # Firewall Rules (/rest/firewallrule)
    # ------------------------------------------------------------------

    def _collect_firewall_rules(self) -> None:
        """
        Coleta snapshot das regras de firewall configuradas.
        Executado a cada ciclo mas com deduplicação no DB (upsert por rule_id).
        """
        rules = self._api.get_firewall_rules()
        if not rules:
            logger.info("Firewall rules: endpoint /rest/firewallrule sem dados (vazio ou 404)")
            return
        for rule in rules:
            self._db.upsert_firewall_rule(rule)
        enabled = sum(1 for r in rules if r.get("enabled", True))
        logger.info("Firewall rules: {} regras ({} ativas)", len(rules), enabled)

    # ------------------------------------------------------------------
    # Port Forwards (/list/portforward)
    # ------------------------------------------------------------------

    def _collect_port_forwards(self) -> None:
        """
        Coleta regras de port forwarding configuradas.
        """
        rules = self._api.get_port_forwards()
        if not rules:
            logger.info("Port forwards: endpoint /list/portforward sem dados (vazio ou 404)")
            return
        for rule in rules:
            self._db.upsert_port_forward(rule)
        enabled = sum(1 for r in rules if r.get("enabled", True))
        logger.info("Port forwards: {} regras ({} ativas)", len(rules), enabled)

    # ------------------------------------------------------------------
    # VPN status — remote user sessions + site-to-site tunnels
    # ------------------------------------------------------------------

    def _collect_vpn_status(self) -> None:
        """
        Coleta status de VPN de todas as fontes disponíveis, em ordem de prioridade:
          1. /stat/remoteuservpn  — sessões de usuário remoto (OpenVPN/L2TP)
          2. /stat/ipsecvpn       — túneis IPSec site-to-site (legacy v1, cookie auth)
          3. system-log VPN       — eventos de conexão/desconexão de túneis (firmware 8.x+)
          4. /stat/device         — campos VPN embarcados no gateway (fallback final)
        """
        ts = datetime.utcnow()
        records: List[Dict] = []

        # ── 1. Sessões de usuário remoto ──────────────────────────────
        sessions = self._api.get_vpn_clients()
        for s in sessions:
            name = (
                s.get("name") or s.get("username")
                or s.get("real_ip") or "Remote User"
            )
            records.append({
                "tunnel_name": name,
                "status":      "running",
                "remote_ip":   s.get("real_ip") or s.get("remote_ip"),
                "uptime":      s.get("uptime") or s.get("connected_at"),
            })
        if sessions:
            logger.debug("VPN: {} sessões de usuário remoto", len(sessions))

        # ── 2. Túneis site-to-site (/stat/ipsecvpn) ──────────────────
        s2s_list = self._api.get_site_to_site_vpn()
        for t in s2s_list:
            raw_status = str(t.get("status") or "").upper()
            if raw_status in ("CONNECTED", "UP", "ACTIVE"):
                running = True
            elif raw_status in ("DISCONNECTED", "DOWN", "INACTIVE"):
                running = False
            else:
                running = bool(
                    t.get("running") or t.get("is_up") or t.get("established")
                )
            uptime_val = t.get("uptime") or t.get("uptimeSec")
            try:
                uptime_sec: Optional[int] = int(uptime_val) if uptime_val is not None else None
            except (TypeError, ValueError):
                uptime_sec = None
            tname = (
                t.get("name") or t.get("_id")
                or t.get("remoteHost") or t.get("remote_gateway") or "IPSec"
            )
            remote = (
                t.get("remoteHost") or t.get("remote_gateway")
                or t.get("peer_ip") or t.get("remote_host")
            )
            records.append({
                "tunnel_name": tname,
                "status":      "running" if running else "down",
                "remote_ip":   remote,
                "uptime":      uptime_sec,
            })
        if s2s_list:
            logger.info("VPN: {} túneis site-to-site via /stat/ipsecvpn", len(s2s_list))

        # ── 3. System-log VPN + /stat/health ─────────────────────────────
        # Formato dos eventos (Network 10.3.58 / firmware 5.0.16):
        #   event: "VPN_SITE_TO_SITE_CONNECTED" | "VPN_SITE_TO_SITE_DISCONNECTED"
        #   parameters.NETWORK.name  → nome do túnel (ex: "VIVO-DC")
        #   parameters.REMOTE_IP.name → IP remoto
        #   parameters.WAN_ID.name   → interface WAN usada
        #
        # O syslog só armazena eventos não-reconhecidos (status=NEW). Eventos
        # de reconexão são purgados rapidamente → não refletem estado ATUAL.
        # Por isso usamos o syslog apenas para descobrir nomes/IPs dos túneis
        # e o /stat/health para confirmar o estado operacional corrente.
        if not s2s_list:
            import time as _time
            vpn_events = self._api.get_vpn_syslog_events(page_size=200)

            # Extrair metadados dos túneis (nome, IP remoto, WAN) do syslog
            tunnel_meta: Dict[str, Dict] = {}
            for ev in vpn_events:
                params  = ev.get("parameters") or {}
                network = params.get("NETWORK") or {}
                tname   = network.get("name")
                if not tname:
                    continue
                if tname not in tunnel_meta:
                    tunnel_meta[tname] = {
                        "remote_ip": (params.get("REMOTE_IP") or {}).get("name"),
                        "wan":       (params.get("WAN_ID")    or {}).get("name"),
                        "vpn_type":  network.get("vpn_type", "ipsec-vpn"),
                    }

            if tunnel_meta:
                import time as _time
                from datetime import datetime as _dt

                # /stat/health vpn="error" no firmware 10.3.58 mesmo com
                # túneis operacionais — não é confiável para status real.
                # Logar apenas para referência; não usar na decisão.
                health_data = self._api.get_health()
                health_subsystems = {
                    sub.get("subsystem", "").lower(): sub.get("status", "")
                    for sub in health_data if sub.get("subsystem")
                }
                logger.debug("VPN: health subsystems (informativo): {}", health_subsystems)

                # ── Heurística por timestamp dos eventos syslog ──────────
                # Syslog guarda apenas eventos não-reconhecidos (status=NEW).
                # Eventos CONNECTED são auto-reconhecidos e purgados.
                # Se o DISCONNECTED mais recente for antigo (> 2h), o túnel
                # reconectou e está online (evento de reconexão foi purgado).
                def _parse_ts(ev: Dict) -> float:
                    raw = ev.get("time") or ev.get("timestamp")
                    if raw:
                        try:
                            ts = float(raw)
                            return ts / 1000 if ts > 4_102_444_800 else ts
                        except (ValueError, TypeError):
                            pass
                    raw = ev.get("datetime") or ev.get("date")
                    if raw:
                        try:
                            return _dt.fromisoformat(
                                str(raw).replace("Z", "+00:00")
                            ).timestamp()
                        except (ValueError, TypeError):
                            pass
                    return 0.0

                now_ts     = _time.time()
                timestamps = [_parse_ts(ev) for ev in vpn_events]
                newest_ts  = max(timestamps) if timestamps else 0.0
                age_hours  = (now_ts - newest_ts) / 3600 if newest_ts else 999.0
                vpn_health_ok = age_hours > 2
                logger.info(
                    "VPN: evento mais recente tem {:.1f}h → {}",
                    age_hours,
                    "online" if vpn_health_ok else "offline",
                )

                status_str = "running" if vpn_health_ok else "down"
                for tname, meta in tunnel_meta.items():
                    records.append({
                        "tunnel_name": tname,
                        "status":      status_str,
                        "remote_ip":   meta["remote_ip"],
                        "uptime":      None,
                    })
                logger.info(
                    "VPN: {} túneis ({}) via syslog+health",
                    len(tunnel_meta),
                    "online" if vpn_health_ok else "offline",
                )

        # ── 4. Dados de VPN embarcados no device (gateway) ────────────
        if not records:
            devices = self._api.get_devices()
            for dev in devices:
                dev_name = dev.get("name") or dev.get("mac")
                # Logar todas as chaves VPN/IPSec para diagnóstico
                vpn_keys_found = [
                    k for k in dev.keys()
                    if "vpn" in k.lower() or "ipsec" in k.lower()
                ]
                if vpn_keys_found:
                    logger.debug("VPN: device '{}' tem chaves: {}", dev_name, vpn_keys_found)
                for vpn_key in (
                    "vpn_link_table", "ipsec_link_table",
                    "vpn_table",       "ipsec_table",
                    "vpn_peer_table",  "ipsec_peer_table",
                ):
                    vpn_data = dev.get(vpn_key)
                    if not isinstance(vpn_data, list) or not vpn_data:
                        continue
                    logger.info(
                        "VPN: device '{}' → campo '{}' com {} entradas",
                        dev_name, vpn_key, len(vpn_data),
                    )
                    for t in vpn_data:
                        running = bool(
                            t.get("running") or t.get("established")
                            or t.get("connected") or t.get("is_up")
                        )
                        uptime_val2 = t.get("uptime")
                        try:
                            uptime_sec2: Optional[int] = (
                                int(uptime_val2) if uptime_val2 is not None else None
                            )
                        except (TypeError, ValueError):
                            uptime_sec2 = None
                        records.append({
                            "tunnel_name": (
                                t.get("name") or t.get("peer_name")
                                or t.get("remote_gateway") or "VPN Tunnel"
                            ),
                            "status":    "running" if running else "down",
                            "remote_ip": t.get("remote_gateway") or t.get("peer_ip"),
                            "uptime":    uptime_sec2,
                        })
                    break

        if records:
            running_count = sum(1 for r in records if r["status"] == "running")
            self._db.insert_vpn_statuses(records, ts)
            logger.info("VPN: {}/{} túneis/sessões online", running_count, len(records))
        else:
            logger.warning("VPN: nenhum dado encontrado em nenhuma fonte")
