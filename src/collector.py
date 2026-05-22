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
            self._collect_wan_status()
            self._process_events()
            self._collect_dpi()
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
            self._db.upsert_client(data)

        self._client_map = self._db.get_all_clients_map()
        logger.debug("Client registry synced: {} devices", len(merged))

    # ------------------------------------------------------------------
    # Step 2: WAN status snapshot
    # ------------------------------------------------------------------

    def _collect_wan_status(self) -> None:
        health_data = self._api.get_health()
        ts = datetime.utcnow()

        for subsystem in health_data:
            sub = subsystem.get("subsystem", "")
            if sub not in ("wan", "wan2"):
                continue

            self._db.insert_wan_status({
                "interface": "WAN2" if sub == "wan2" else "WAN",
                "status":    subsystem.get("status", "unknown"),
                "uptime":    subsystem.get("uptime"),
                "latency":   subsystem.get("latency"),
                "rx_bytes":  subsystem.get("rx_bytes-r"),
                "tx_bytes":  subsystem.get("tx_bytes-r"),
                "wan_ip":    subsystem.get("wan_ip"),
                "timestamp": ts,
            })
        logger.debug("WAN status snapshot saved")

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
