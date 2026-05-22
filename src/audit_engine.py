"""
Audit Engine — post-processing layer that runs after each collection cycle.

Responsibilities:
  1. Detect suspicious devices (burst of blocks in a short window).
  2. Enrich firewall-block and threat records with client display names.
  3. Classify events into rule_type (traffic_rule vs firewall_rule).
  4. Infer content category from rule name / event message when not explicit.
  5. Infer device type from UniFi fingerprint, hostname patterns and OUI vendor.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Dict, Optional

from loguru import logger

from src.api_client import UniFiAPIClient
from src.database_manager import DatabaseManager


class AuditEngine:
    def __init__(
        self,
        db: DatabaseManager,
        suspicious_threshold: int = 5,
        suspicious_window_minutes: int = 1,
    ) -> None:
        self._db = db
        self._threshold = suspicious_threshold
        self._window = timedelta(minutes=suspicious_window_minutes)

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def run(self) -> None:
        """Execute all audit checks.  Called after each collection cycle."""
        self._detect_suspicious_bursts()

    # ------------------------------------------------------------------
    # Suspicious-burst detection
    # ------------------------------------------------------------------

    def _detect_suspicious_bursts(self) -> None:
        """
        Flag any client that triggered >= threshold blocks within the
        sliding window.  The check is done against the last N minutes of
        newly-inserted blocks.
        """
        recent_blocks = self._db.get_recent_blocks(limit=2000)
        if recent_blocks.empty:
            return

        cutoff = datetime.utcnow() - self._window
        recent = recent_blocks[recent_blocks["timestamp"] >= cutoff]
        if recent.empty:
            return

        per_client = recent.groupby("client_mac").size()
        for mac, count in per_client.items():
            if mac and count >= self._threshold:
                reason = (
                    f"{count} blocks in the last {int(self._window.total_seconds() // 60)} min "
                    f"(threshold: {self._threshold})"
                )
                self._db.mark_suspicious(mac, reason)

    # ------------------------------------------------------------------
    # Device type inference
    # ------------------------------------------------------------------

    @staticmethod
    def infer_device_type(
        dev_cat: str = "",
        vendor: str = "",
        hostname: str = "",
        os_name: str = "",
    ) -> str:
        """
        Classifies a device into one of the standard device type categories
        using a priority chain: UniFi fingerprint → hostname patterns → OUI vendor.

        Returns one of: phone, computer, tablet, gaming, tv, iot,
                        printer, camera, unknown
        """
        # 1. UniFi fingerprint (dev_cat) — pode ser int ou string dependendo do firmware
        # Mapeamento numérico (UniFi OS 5.x retorna inteiros)
        _int_map = {
            0: "unknown", 1: "computer", 2: "phone", 3: "tablet",
            4: "gaming",  5: "tv",       6: "iot",   7: "printer",
            8: "camera",  9: "infrastructure",
        }
        if isinstance(dev_cat, int):
            mapped = _int_map.get(dev_cat)
            if mapped and mapped != "unknown":
                return mapped
            dev_cat = ""  # cai para hostname/vendor

        cat = str(dev_cat or "").lower()
        cat_map = {
            "mobile":         "phone",
            "phone":          "phone",
            "smartphone":     "phone",
            "laptop":         "computer",
            "desktop":        "computer",
            "pc":             "computer",
            "tablet":         "tablet",
            "gaming":         "gaming",
            "game console":   "gaming",
            "tv":             "tv",
            "smart tv":       "tv",
            "streaming":      "tv",
            "iot":            "iot",
            "home automation": "iot",
            "smart home":     "iot",
            "printer":        "printer",
            "ip camera":      "camera",
            "camera":         "camera",
        }
        for k, v in cat_map.items():
            if k in cat:
                return v

        # 2. Hostname patterns — more reliable than vendor for Apple
        hn = (hostname or "").lower()
        hostname_rules = [
            ("phone",    ["iphone", "android", "pixel", "galaxy", "huawei-", "xiaomi",
                          "mi-", "oneplus", "oppo", "vivo", "redmi", "moto", "nokia-",
                          "sony-xperia", "lg-", "htc-", "poco", "realme-"]),
            ("tablet",   ["ipad", "tablet", "kindle", "fire-hd", "surface-"]),
            ("computer", ["macbook", "imac", "mac-", "laptop", "thinkpad", "precision",
                          "latitude", "pavilion", "inspiron", "elitebook", "matebook",
                          "zenbook", "desktop", "pc-", "workstation", "nuc-",
                          "vivobook", "aspire", "swift-", "chromebook"]),
            ("gaming",   ["playstation", "ps4", "ps5", "xbox", "nintendo", "switch",
                          "steamdeck", "steam-deck", "retropie"]),
            ("tv",       ["appletv", "apple-tv", "firetv", "fire-tv", "chromecast",
                          "roku", "shield", "androidtv", "smart-tv", "bravia",
                          "lgtv", "samsungtv", "samsung-tv", "philips-tv", "tcl-"]),
            ("iot",      ["esp32", "esp8266", "arduino", "raspberry", "homeassist",
                          "sonoff", "tasmota", "shelly", "ring-", "nest-", "echo-",
                          "alexa", "wemo", "tp-link", "tplink", "kasa-", "tuya-",
                          "zigbee", "zwave", "smartplug", "smart-plug", "meross",
                          "govee", "wyze-", "ewelink"]),
            ("printer",  ["printer", "print-", "hp-laser", "canon-", "epson-",
                          "brother-", "ricoh-", "xerox-", "kyocera-"]),
            ("camera",   ["ipcam", "hikvision", "dahua", "reolink", "eufy-cam",
                          "arlo-", "amcrest", "axis-", "foscam", "tapo-"]),
        ]
        for dtype, patterns in hostname_rules:
            if any(p in hn for p in patterns):
                return dtype

        # 3. Vendor / OUI
        v = (vendor or "").lower()
        if "apple" in v:
            # Apple makes iPhones, iPads AND Macs — use hostname to distinguish
            if any(p in hn for p in ["iphone", "ipad", "ipod"]):
                return "phone"
            return "computer"
        if any(x in v for x in ["samsung", "huawei", "xiaomi", "motorola",
                                  "oneplus", "oppo", "vivo", "realme", "nokia",
                                  "google", "htc", "zte", "tcl communic"]):
            return "phone"
        if any(x in v for x in ["dell", "hewlett", "hp inc", "lenovo", "acer",
                                  "asus tek", "microsoft", "toshiba", "fujitsu",
                                  "msi ", "gigabyte", "intel corp"]):
            return "computer"
        if any(x in v for x in ["roku", "lg electron", "vizio", "hisense",
                                  "sharp", "philips", "tcl"]):
            return "tv"
        if any(x in v for x in ["amazon", "espressif", "raspberry pi",
                                  "tp-link", "tuya", "shenzhen", "sonoff"]):
            return "iot"
        if any(x in v for x in ["nintendo", "sony interac", "valve"]):
            return "gaming"
        if any(x in v for x in ["canon", "epson", "brother", "xerox", "ricoh",
                                  "kyocera", "konica", "lexmark"]):
            return "printer"
        if any(x in v for x in ["hikvision", "dahua", "axis communic",
                                  "hanwha", "vivotek"]):
            return "camera"

        return "unknown"

    # ------------------------------------------------------------------
    # Event classification helpers (used by collector)
    # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    # Classificadores para API v1 /stat/event  (firmware legado)
    # ------------------------------------------------------------------

    @staticmethod
    def classify_rule_type(event: Dict[str, Any]) -> str:
        """
        Mapeia evento v1 → 'traffic_rule' ou 'firewall_rule'.
        Traffic Rules atuam sobre categorias DPI; Firewall Rules sobre IP/porta.
        """
        key = event.get("key", "")
        msg = event.get("msg", "")

        if "traffic_rule" in key.lower() or "traffic rule" in msg.lower():
            return "traffic_rule"
        if "app" in key.lower() or "category" in msg.lower():
            return "traffic_rule"
        return "firewall_rule"

    @staticmethod
    def extract_category(event: Dict[str, Any]) -> Optional[str]:
        """Infere categoria de conteúdo de evento v1."""
        if event.get("cat_name"):
            return event["cat_name"]

        app = event.get("app_name") or event.get("app", "")
        if app:
            return UniFiAPIClient.infer_category_from_text(app) or app

        rule = event.get("rule_name", "")
        if rule:
            return UniFiAPIClient.infer_category_from_text(rule) or rule

        msg = event.get("msg", "")
        if msg:
            return UniFiAPIClient.infer_category_from_text(msg)

        return None

    @staticmethod
    def extract_severity(event: Dict[str, Any]) -> str:
        """Normaliza severidade de evento v1 → critical/high/medium/low."""
        raw = str(event.get("severity", "")).lower()
        if raw in ("0", "critical", "emergency", "alert"):
            return "critical"
        if raw in ("1", "high", "error"):
            return "high"
        if raw in ("2", "medium", "warning"):
            return "medium"
        return "low"

    # ------------------------------------------------------------------
    # Classificadores para system-log v2  (firmware 8.x+ / UniFi OS 3.x+)
    # ------------------------------------------------------------------

    @staticmethod
    def classify_rule_type_syslog(
        event: Dict[str, Any], rule_name: str
    ) -> str:
        """
        Determina o tipo de regra a partir de evento do system-log v2.

        Verifica campos 'type' e 'event' (UniFi OS 5.x):
          type = CONTENT_FILTERING_AND_RESTRICTIONS → traffic_rule
          type = TRAFFIC_RULE_BLOCK                 → traffic_rule
          event/key = BLOCKED_BY_FIREWALL           → firewall_rule
        """
        ev_type  = str(event.get("type")  or event.get("eventType") or "").upper()
        ev_event = str(event.get("event") or event.get("key")       or "").upper()

        if "TRAFFIC_RULE" in ev_type or "TRAFFIC_RULE" in ev_event:
            return "traffic_rule"
        # Filtragem de conteúdo usa traffic rules no UniFi OS 5.x
        if "CONTENT_FILTERING" in ev_type or "CONTENT_FILTER" in ev_type:
            return "traffic_rule"
        if "FIREWALL" in ev_type or "FIREWALL" in ev_event or "FW" in ev_type:
            return "firewall_rule"

        rn_lower = rule_name.lower()
        if "traffic" in rn_lower or rn_lower.startswith("tr "):
            return "traffic_rule"

        return "firewall_rule"

    @staticmethod
    def extract_category_syslog(
        event: Dict[str, Any], rule_name: str, message: str
    ) -> Optional[str]:
        """
        Infere categoria de conteúdo de evento do system-log v2.

        Prioridade:
          1. Campo 'type' (UniFi OS 5.x) → categoria legível
          2. Campos explícitos de app/categoria
          3. Nome da regra → inferência ou uso direto
          4. Texto da mensagem
        """
        # 1. Campo 'type' do system-log v2 (mais confiável)
        _TYPE_CAT = {
            "CONTENT_FILTERING_AND_RESTRICTIONS": "Content Filtering",
            "SECURITY_FIREWALL":  "Firewall Block",
            "SECURITY_IDS_IPS":   "IDS/IPS",
            "INTERNET_SECURITY":  "Internet Security",
            "HONEYPOT":           "Honeypot",
        }
        ev_type = str(event.get("type") or "").upper()
        for _key, _cat in _TYPE_CAT.items():
            if _key in ev_type:
                return _cat

        # 2. Campos explícitos de categoria/aplicação
        cat = (
            event.get("category") or event.get("appCategory")
            or event.get("applicationCategory") or event.get("cat_name")
        )
        if cat and cat not in ("SECURITY", "AUDIT"):
            return cat

        app = event.get("application") or event.get("app") or event.get("appName")
        if app:
            return UniFiAPIClient.infer_category_from_text(str(app)) or str(app)

        # 3. Nome da regra
        if rule_name:
            inferred = UniFiAPIClient.infer_category_from_text(rule_name)
            if inferred:
                return inferred
            if len(rule_name) > 3 and rule_name.lower() not in ("drop", "block", "deny"):
                return rule_name

        # 4. Texto da mensagem
        if message:
            return UniFiAPIClient.infer_category_from_text(message)

        return None
