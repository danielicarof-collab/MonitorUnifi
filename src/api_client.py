"""
Native HTTP client para UniFi Network API (UDM-Pro / UDM / CloudKey).

Suporta múltiplas versões do UniFi Network Application:
  - API v1            (/proxy/network/api/s/{site}/...)           — firmware legado
  - API v2            (/proxy/network/v2/api/site/{site}/...)     — firmware 8.4+
  - Integrations v1   (/proxy/network/integrations/v1/sites/...) — UniFi OS 5.x+ / Network 10.x+
  - System-Log        (/proxy/network/v2/api/site/{site}/system-log/all)
                                                                   — UniFi OS 3.x+ (firmware 8.x+)

Autenticação (em ordem de preferência):
  - API Key via header X-API-Key                                   (UniFi OS 5.x+ / Network 10.x+)
    → Gerada em: UniFi OS → Settings → API → Create API Key
    → Não requer login/logout, não está sujeita a rate-limit (429)
    → Necessária para endpoints /proxy/network/integrations/v1/...
  - Cookie TOKEN (JWT) + csrfToken extraído do payload do JWT      (UniFi OS 3.x+)
  - Cookie csrf_token separado                                      (UniFi OS ≤ 2.x)

O cliente detecta automaticamente o site, extrai o CSRF do JWT e faz
fallback transparente entre endpoints para compatibilidade máxima.
"""
import base64
import json as _json
import urllib3
from typing import Any, Dict, List, Optional, Tuple

import requests
from loguru import logger

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── DPI category IDs ─────────────────────────────────────────────────
DPI_CATEGORIES: Dict[int, str] = {
    0:  "Other",          1:  "Chat",           2:  "VoIP",
    3:  "Streaming",      4:  "Multimedia",      5:  "Gaming",
    6:  "P2P",            7:  "Social Media",    8:  "Internet",
    9:  "Anti-Virus",     10: "Search Engines",  11: "VPN & Tunneling",
    12: "News",           13: "Email",           14: "Network Services",
    15: "Remote Desktop", 16: "File Sharing",    17: "Business",
    18: "Video Streaming",19: "Utilities",       20: "Flash",
    21: "Adult Content",  22: "Mobile Apps",     23: "Online Games",
    24: "Cloud Storage",  25: "Shopping",
}

BLOCK_EVENT_KEYS  = {"EVT_FW_", "EVT_TRAFFIC_RULE_", "EVT_FIREWALL_"}
THREAT_EVENT_KEYS = {"EVT_IPS_", "EVT_IDPS_", "EVT_THREAT_"}

APP_CATEGORY_MAP: Dict[str, str] = {
    "youtube":   "Video Streaming", "netflix":   "Video Streaming",
    "twitch":    "Video Streaming", "tiktok":    "Social Media",
    "instagram": "Social Media",    "facebook":  "Social Media",
    "twitter":   "Social Media",    "whatsapp":  "Chat",
    "telegram":  "Chat",            "discord":   "Chat / Gaming",
    "pornhub":   "Adult Content",   "xvideos":   "Adult Content",
}


class UniFiAPIClient:
    """
    HTTP client para UniFi Network API (UDM-Pro / UDM / CloudKey).

    Faz descoberta automática do site e tenta múltiplas versões de
    endpoint para garantir compatibilidade entre firmwares.
    """

    def __init__(
        self,
        host: str,
        username: str = "",
        password: str = "",
        site: str = "default",
        verify_ssl: bool = False,
        api_key: Optional[str] = None,
    ) -> None:
        self.host       = host.rstrip("/")
        self.username   = username
        self.password   = password
        self.site       = site          # pode ser atualizado por discover_site()
        self.verify_ssl = verify_ssl

        # API Key (UniFi OS 5.x+ / Network 10.x+)
        # Quando presente, substitui autenticação por cookie/CSRF completamente.
        self._api_key: Optional[str] = api_key.strip() if api_key else None
        self._use_api_key: bool      = bool(self._api_key)

        self._session        = requests.Session()
        self._session.verify = verify_ssl
        self._csrf_token: Optional[str] = None
        self._authenticated: bool       = False

    # ── bases de URL ─────────────────────────────────────────────────

    @property
    def _base_v1(self) -> str:
        """API v1 — padrão na maioria das versões."""
        return f"{self.host}/proxy/network/api/s/{self.site}"

    @property
    def _base_v2(self) -> str:
        """API v2 — introduzida no UniFi Network 8.4+."""
        return f"{self.host}/proxy/network/v2/api/site/{self.site}"

    @property
    def _base_integrations_v1(self) -> str:
        """Integrations API v1 — UniFi OS 5.x+ / Network 10.x+. Requer API Key."""
        return f"{self.host}/proxy/network/integrations/v1/sites/{self.site}"

    # ── autenticação ─────────────────────────────────────────────────

    @staticmethod
    def _extract_csrf_from_jwt(token: str) -> Optional[str]:
        """
        Extrai o csrfToken do payload do JWT armazenado no cookie TOKEN.

        UniFi OS 3.x+ não usa cookie separado 'csrf_token' — em vez disso
        incorpora o csrfToken dentro do próprio JWT de autenticação.

        Formato JWT: header.payload.signature  (base64url)
        Payload decodificado contém: {"csrfToken": "uuid...", ...}
        """
        if not token:
            return None
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return None
            # base64url → base64 padrão (adiciona padding se necessário)
            padded = parts[1] + "=" * (-len(parts[1]) % 4)
            payload = _json.loads(base64.b64decode(padded).decode("utf-8"))
            return payload.get("csrfToken") or payload.get("csrf_token")
        except Exception:
            return None

    def login(self) -> bool:
        # Não tenta novo login se já está autenticado
        if self._authenticated:
            return True

        # Com API Key, não há login por cookie — apenas marca como autenticado
        if self._use_api_key:
            self._authenticated = True
            logger.info("API Key authentication ativo — sem login por cookie necessário.")
            return True

        url     = f"{self.host}/api/auth/login"
        payload = {"username": self.username, "password": self.password,
                   "rememberMe": False, "token": ""}
        try:
            resp = self._session.post(url, json=payload, timeout=15)

            # 429 = rate limit do UDM-Pro (muitas tentativas de login)
            if resp.status_code == 429:
                logger.error(
                    "429 Too Many Requests — o UDM-Pro bloqueou o IP por "
                    "excesso de tentativas de login. Aguarde 5 minutos e tente novamente."
                )
                self._authenticated = False
                return False

            resp.raise_for_status()
            # Extrai CSRF token — ordem de prioridade por versão de firmware:
            # 1. Cookie direto "csrf_token"  (UniFi OS ≤ 2.x / antigos)
            # 2. Header X-CSRF-Token         (alguns firmwares intermediários)
            # 3. Dentro do JWT "TOKEN"       (UniFi OS 3.x+ / UDM-Pro atual)
            self._csrf_token = (
                self._session.cookies.get("csrf_token")
                or resp.headers.get("X-CSRF-Token")
                or resp.headers.get("x-csrf-token")
                or self._extract_csrf_from_jwt(
                    self._session.cookies.get("TOKEN", "")
                )
            )
            if self._csrf_token:
                logger.debug("CSRF token obtido: {}…", self._csrf_token[:12])
            else:
                logger.debug("CSRF token não encontrado — continuando sem ele.")
            self._authenticated = True
            logger.info("Authenticated with UniFi API at {}", self.host)
            return True
        except requests.RequestException as exc:
            logger.error("UniFi authentication failed: {}", exc)
            self._authenticated = False
            return False

    def logout(self) -> None:
        if self._use_api_key:
            # API Key não usa sessão por cookie — sem requisição de logout necessária
            self._authenticated = False
            logger.info("API Key session encerrada (sem requisição de logout).")
            return
        try:
            self._session.post(f"{self.host}/api/auth/logout", timeout=5)
        except Exception:
            pass
        self._authenticated = False
        self._session.cookies.clear()
        logger.info("Logged out from UniFi API")

    # ── descoberta de site ────────────────────────────────────────────

    def discover_site(self) -> str:
        """
        Retorna o nome/ID real do primeiro site acessível.

        Quando API Key está configurada, usa o endpoint de integrations.
        Caso contrário, tenta vários endpoints legados em ordem.
        Atualiza self.site se encontrar algo diferente de 'default'.
        """
        if not self._authenticated:
            self.login()

        # ── Modo API Key: usa endpoint de integrations ────────────────
        if self._use_api_key:
            url = f"{self.host}/proxy/network/integrations/v1/sites"
            resp = self._get_raw(url)
            if resp and resp.status_code == 200:
                try:
                    body  = resp.json()
                    sites = body.get("data", body)
                    if isinstance(sites, list) and sites:
                        first = sites[0]
                        name  = (
                            first.get("name")
                            or first.get("id")
                            or first.get("_id")
                            or "default"
                        )
                        if name and name != self.site:
                            logger.info(
                                "Site auto-detectado via API Key: '{}' → '{}'.",
                                self.site, name,
                            )
                            self.site = name
                        else:
                            logger.info("Site confirmado via API Key: '{}'", self.site)
                        all_names = [s.get("name") or s.get("id") or "?" for s in sites]
                        logger.debug("Sites disponíveis (integrations): {}", all_names)
                        return self.site
                except Exception:
                    pass
            logger.warning(
                "Não foi possível listar sites via API Key — mantendo '{}'.", self.site
            )
            return self.site

        # ── Modo legado: cookie/CSRF ──────────────────────────────────
        candidates = [
            # v1 — clássico
            f"{self.host}/proxy/network/api/self/sites",
            # v2
            f"{self.host}/proxy/network/v2/api/site",
            # legacy (controladores não-UDM)
            f"{self.host}/api/self/sites",
        ]

        headers = {"Content-Type": "application/json"}
        if self._csrf_token:
            headers["X-Csrf-Token"] = self._csrf_token

        for url in candidates:
            try:
                resp = self._session.get(url, headers=headers, timeout=10)
                if resp.status_code != 200:
                    continue
                body  = resp.json()
                sites = body.get("data", body)
                if isinstance(sites, list) and sites:
                    # Prefere o nome mais curto/legível
                    first = sites[0]
                    name  = (
                        first.get("name")
                        or first.get("id")
                        or first.get("_id")
                        or "default"
                    )
                    if name and name != self.site:
                        logger.info(
                            "Site auto-detectado: '{}' (configurado: '{}'). "
                            "Atualizando.", name, self.site
                        )
                        self.site = name
                    else:
                        logger.info("Site confirmado: '{}'", self.site)

                    # Exibe todos os sites disponíveis para diagnóstico
                    all_names = [
                        s.get("name") or s.get("id") or "?"
                        for s in sites
                    ]
                    logger.debug("Sites disponíveis: {}", all_names)
                    return self.site
            except Exception:
                continue

        logger.warning(
            "Não foi possível listar os sites — mantendo '{}'. "
            "Verifique se o usuário tem permissão de leitura.", self.site
        )
        return self.site

    # ── helper interno ────────────────────────────────────────────────

    def _headers(self) -> Dict[str, str]:
        h = {"Content-Type": "application/json"}
        if self._use_api_key:
            # Autenticação via API Key (UniFi OS 5.x+ / Network 10.x+)
            h["X-API-Key"] = self._api_key
        elif self._csrf_token:
            h["X-Csrf-Token"] = self._csrf_token
        return h

    def _get_raw(self, url: str, **kwargs) -> Optional[requests.Response]:
        """GET autenticado retornando o objeto Response (sem parse)."""
        if not self._authenticated:
            if not self.login():
                return None  # inclui falha por 429 — não tenta de novo
        try:
            resp = self._session.get(url, headers=self._headers(),
                                     timeout=30, **kwargs)
            if resp.status_code == 401:
                # Sessão expirou — tenta relogin UMA única vez
                logger.warning("Sessão expirada — re-autenticando…")
                self._authenticated = False
                if not self.login():
                    return None
                resp = self._session.get(url, headers=self._headers(),
                                         timeout=30, **kwargs)
            return resp
        except requests.Timeout:
            logger.warning("Timeout em GET {}", url)
            return None
        except requests.RequestException as exc:
            logger.error("Erro de rede em GET {}: {}", url, exc)
            return None

    def _request(self, method: str, endpoint: str, **kwargs) -> Optional[Any]:
        """Requisição v1 autenticada com parse de JSON."""
        if not self._authenticated:
            if not self.login():
                return None

        url = f"{self._base_v1}{endpoint}"
        try:
            resp = self._session.request(
                method, url, headers=self._headers(), timeout=30, **kwargs
            )
            if resp.status_code == 401:
                logger.warning("Sessão expirada — re-autenticando…")
                self._authenticated = False
                if not self.login():
                    return None
                resp = self._session.request(
                    method, url, headers=self._headers(), timeout=30, **kwargs
                )

            if resp.status_code == 404:
                # Distingue "endpoint inexistente" de "coleção vazia":
                # O UniFi retorna HTTP 404 + api.err.NotFound quando o log
                # de eventos/alarmes está vazio (comportamento não-padrão).
                # Nesses casos retornamos [] em vez de None para não acionar
                # o fallback v2 desnecessariamente.
                try:
                    body = resp.json()
                    if body.get("meta", {}).get("msg") == "api.err.NotFound":
                        logger.debug("Coleção vazia em {} — retornando []", endpoint)
                        return []
                except Exception:
                    pass
                return None  # Endpoint realmente ausente → fallback v2

            resp.raise_for_status()
            body = resp.json()

            # Trata api.err.NotFound em corpo HTTP 200 (evento/alarme vazio
            # em algumas versões do firmware retorna 200 + rc=error)
            meta = body.get("meta", {})
            if isinstance(meta, dict) and meta.get("rc") == "error":
                logger.debug("API retornou rc=error em {}: {}", endpoint,
                             meta.get("msg", ""))
                return []   # lista vazia — não é None (evita fallback desnecessário)

            return body.get("data", body)

        except requests.Timeout:
            logger.warning("Timeout em {} {}", method, endpoint)
            return None
        except requests.RequestException as exc:
            logger.error("API error [{} {}]: {}", method, endpoint, exc)
            return None
        except ValueError as exc:
            logger.error("JSON parse error em {}: {}", endpoint, exc)
            return None

    def _request_v2(self, endpoint: str, **kwargs) -> Optional[Any]:
        """Requisição via API v2."""
        url = f"{self._base_v2}{endpoint}"
        resp = self._get_raw(url, **kwargs)
        if resp is None or resp.status_code == 404:
            return None
        try:
            resp.raise_for_status()
            body = resp.json()
            return body.get("data", body)
        except Exception:
            return None

    def _request_integrations(self, endpoint: str, **kwargs) -> Optional[Any]:
        """
        Requisição via Integrations API v1 (UniFi OS 5.x+ / Network 10.x+).

        Base: /proxy/network/integrations/v1/sites/{siteId}{endpoint}
        Requer API Key (header X-API-Key). Funciona também com sessão de cookie,
        mas o uso primário é com api_key configurada.

        Retorna o campo 'data' do JSON, ou None em caso de erro/ausência.
        """
        if not self._authenticated:
            if not self.login():
                return None

        url = f"{self._base_integrations_v1}{endpoint}"
        try:
            resp = self._session.get(url, headers=self._headers(), timeout=30, **kwargs)
            if resp.status_code == 401:
                if self._use_api_key:
                    logger.error("API Key inválida ou sem permissão para {} (401).", endpoint)
                    return None
                logger.warning("Sessão expirada (integrations) — re-autenticando…")
                self._authenticated = False
                if not self.login():
                    return None
                resp = self._session.get(url, headers=self._headers(), timeout=30, **kwargs)
            if resp.status_code == 404:
                logger.debug("Integrations endpoint ausente: {} — firmware não suportado?", endpoint)
                return None
            if resp.status_code == 403:
                logger.warning(
                    "403 Forbidden em {} — API Key sem permissão ou endpoint requer acesso especial.",
                    endpoint,
                )
                return None
            resp.raise_for_status()
            body = resp.json()
            return body.get("data", body)
        except requests.Timeout:
            logger.warning("Timeout em integrations GET {}", endpoint)
            return None
        except requests.RequestException as exc:
            logger.error("Integrations API error [{}]: {}", endpoint, exc)
            return None
        except ValueError as exc:
            logger.error("JSON parse error em integrations {}: {}", endpoint, exc)
            return None

    def _request_with_fallback(
        self,
        v1_endpoint: str,
        v2_endpoint: str,
        label: str,
        **kwargs,
    ) -> List[Dict]:
        """
        Tenta v1, depois v2, depois loga aviso claro sobre o problema.
        Retorna lista vazia em caso de falha total (nunca lança exceção).
        """
        # Tentativa v1
        result = self._request("GET", v1_endpoint, **kwargs)
        if result is not None:
            return result if isinstance(result, list) else []

        # Tentativa v2
        logger.debug("{} — v1 retornou 404, tentando v2…", label)
        result = self._request_v2(v2_endpoint, **kwargs)
        if result is not None:
            logger.info("{} — usando endpoint v2 com sucesso.", label)
            return result if isinstance(result, list) else []

        # Ambos falharam
        logger.warning(
            "{} — endpoints v1 e v2 retornaram 404.\n"
            "  Causas comuns:\n"
            "  1. Usuário 'View Only' sem acesso a eventos — "
            "     tente criar um usuário com role 'Administrator (Read Only)'\n"
            "  2. Site name incorreto — execute: python run.py diagnose\n"
            "  3. Versão do firmware não suporta este endpoint",
            label,
        )
        return []

    # ── endpoints públicos ────────────────────────────────────────────

    def get_active_clients(self) -> List[Dict]:
        result = self._request("GET", "/stat/sta")
        return result if isinstance(result, list) else []

    def get_known_clients(self) -> List[Dict]:
        result = self._request("GET", "/rest/user")
        return result if isinstance(result, list) else []

    def get_health(self) -> List[Dict]:
        result = self._request("GET", "/stat/health")
        return result if isinstance(result, list) else []

    def get_dpi_stats(self) -> List[Dict]:
        result = self._request("GET", "/stat/dpi")
        return result if isinstance(result, list) else []

    def get_events(self, limit: int = 3000, start: int = 0) -> List[Dict]:
        """Log de eventos com fallback automático v1 → v2."""
        return self._request_with_fallback(
            v1_endpoint="/stat/event",
            v2_endpoint="/event",
            label="Events",
            params={"_limit": limit, "_start": start},
        )

    def get_alarms(self) -> List[Dict]:
        """Alarmes IPS/IDS com fallback automático v1 → v2."""
        return self._request_with_fallback(
            v1_endpoint="/stat/alarm",
            v2_endpoint="/alarm",
            label="Alarms",
        )

    def get_devices(self) -> List[Dict]:
        result = self._request("GET", "/stat/device")
        return result if isinstance(result, list) else []

    def get_rogue_aps(self) -> List[Dict]:
        """Fetch neighbouring / rogue APs detected by managed access points."""
        result = self._request("GET", "/stat/rogueap")
        return result if isinstance(result, list) else []

    def get_vpn_clients(self) -> List[Dict]:
        result = self._request("GET", "/stat/remoteuservpn")
        return result if isinstance(result, list) else []

    def get_system_log(
        self,
        categories: Optional[List[str]] = None,
        page_size: int = 500,
        page_num: int = 1,
        ts_from: Optional[int] = None,
        ts_to: Optional[int] = None,
    ) -> Tuple[List[Dict], int]:
        """
        Busca logs do sistema via API v2  (UniFi OS 3.x+ / firmware 8.x+).

        Endpoint : POST /proxy/network/v2/api/site/{site}/system-log/all

        Categorias válidas (confirmadas no firmware 5.0.16 / Network 9.x):
          SECURITY, VPN, INTERNET_AND_WAN, AUDIT, CLIENT_DEVICES,
          UNIFI_DEVICES, SOFTWARE_UPDATES, POWER, UNIFI_ETHERNET_PORTS

        Retorna (lista_de_eventos, total_disponível).
        Retorna ([], 0) se o endpoint não existir (firmware antigo) ou erro.
        """
        if not self._authenticated:
            if not self.login():
                return [], 0

        body: Dict[str, Any] = {
            "categories": categories or ["SECURITY"],
            "pageSize":   page_size,
            "pageNum":    page_num,
        }
        if ts_from is not None:
            body["timestampFrom"] = ts_from
        if ts_to is not None:
            body["timestampTo"] = ts_to

        url = f"{self._base_v2}/system-log/all"

        def _post() -> requests.Response:
            return self._session.post(
                url, json=body, headers=self._headers(), timeout=45
            )

        try:
            resp = _post()

            if resp.status_code == 401:
                logger.warning("Sessão expirada (system-log) — re-autenticando…")
                self._authenticated = False
                if not self.login():
                    return [], 0
                resp = _post()

            if resp.status_code == 404:
                logger.debug("system-log endpoint ausente — firmware antigo?")
                return [], 0

            resp.raise_for_status()
            body_r = resp.json()

            # Flexibilidade: o campo de dados pode ter nomes diferentes
            data = (
                body_r.get("data")
                or body_r.get("logs")
                or body_r.get("events")
                or []
            )
            total = int(
                body_r.get("total_element_count")   # system-log v2 UniFi OS 5.x
                or body_r.get("count")
                or body_r.get("totalCount")
                or body_r.get("total")
                or len(data)
            )
            return (data if isinstance(data, list) else []), total

        except requests.Timeout:
            logger.warning("Timeout ao buscar system-log (page {})", page_num)
            return [], 0
        except requests.RequestException as exc:
            logger.error("Erro de rede em system-log: {}", exc)
            return [], 0
        except (ValueError, KeyError) as exc:
            logger.error("JSON parse error em system-log: {}", exc)
            return [], 0

    # ── diagnóstico completo ──────────────────────────────────────────

    def run_diagnostics(self) -> Dict[str, Any]:
        """
        Testa todos os endpoints e retorna um relatório detalhado.
        Use via: python run.py diagnose

        Faz UMA única autenticação e reutiliza a sessão para todos os testes,
        evitando disparar o rate-limiter (429) do UDM-Pro.
        """
        # Login único — se falhar (inclusive por 429) para tudo aqui
        if not self._authenticated:
            ok = self.login()
        else:
            ok = True

        report: Dict[str, Any] = {
            "host":            self.host,
            "site_configured": self.site,
            "auth_mode":       "api_key" if self._use_api_key else "cookie",
            "authenticated":   self._authenticated,
            "endpoints":       {},
        }

        if not ok:
            report["site_discovered"] = self.site
            for label in ["health","clients","known_clients","dpi",
                          "events_v1","devices","integrations_devices",
                          "integrations_networks"]:
                report["endpoints"][label] = "NÃO TESTADO (falha no login)"
            return report

        # Testa listagem de sites (reutiliza sessão já autenticada)
        report["site_discovered"] = self.discover_site()

        def _classify_get(resp: Optional[requests.Response]) -> str:
            if resp is None:
                return "TIMEOUT/NETWORK_ERROR"
            if resp.status_code == 200:
                try:
                    b = resp.json()
                    d = b.get("data", b)
                    n = len(d) if isinstance(d, list) else "n/a"
                    return f"OK ({n} items)"
                except Exception:
                    return "OK (parse error)"
            if resp.status_code == 401:
                return "401 UNAUTHORIZED"
            if resp.status_code == 403:
                return "403 FORBIDDEN"
            if resp.status_code == 404:
                try:
                    b = resp.json()
                    if b.get("meta", {}).get("msg") == "api.err.NotFound":
                        return "OK (0 items — log vazio)"
                except Exception:
                    pass
                return "404 NOT FOUND"
            return str(resp.status_code)

        # ── Endpoints legados (v1) ───────────────────────────────────────
        legacy_tests: List[Tuple[str, str]] = [
            ("health",        f"{self._base_v1}/stat/health"),
            ("clients",       f"{self._base_v1}/stat/sta"),
            ("known_clients", f"{self._base_v1}/rest/user"),
            ("dpi",           f"{self._base_v1}/stat/dpi"),
            ("devices",       f"{self._base_v1}/stat/device"),
            ("events_v1",     f"{self._base_v1}/stat/event?_limit=5"),
            ("alarms_v1",     f"{self._base_v1}/stat/alarm"),
        ]
        for label, url in legacy_tests:
            report["endpoints"][label] = _classify_get(self._get_raw(url))

        # ── Integrations API v1 (API Key) ────────────────────────────────
        integrations_tests: List[Tuple[str, str]] = [
            ("integrations_sites",    f"{self.host}/proxy/network/integrations/v1/sites"),
            ("integrations_devices",  f"{self._base_integrations_v1}/devices"),
            ("integrations_networks", f"{self._base_integrations_v1}/networks"),
        ]
        for label, url in integrations_tests:
            resp = self._get_raw(url)
            report["endpoints"][label] = _classify_get(resp)

        # ── System-Log (POST) ─────────────────────────────────────────
        for cat in ("SECURITY", "VPN", "INTERNET_AND_WAN"):
            events, total = self.get_system_log(
                categories=[cat], page_size=5, page_num=1
            )
            label = f"syslog_{cat.lower()}"
            if total > 0:
                report["endpoints"][label] = f"OK ({total} items total)"
            elif isinstance(events, list):
                report["endpoints"][label] = "OK (0 items)"
            else:
                report["endpoints"][label] = "ERRO"

        return report

    # ── helpers estáticos ─────────────────────────────────────────────

    @staticmethod
    def dpi_category_name(cat_id: int) -> str:
        return DPI_CATEGORIES.get(cat_id, f"Category {cat_id}")

    @staticmethod
    def is_block_event(event_key: str) -> bool:
        return any(event_key.startswith(p) for p in BLOCK_EVENT_KEYS)

    @staticmethod
    def is_threat_event(event_key: str) -> bool:
        return any(event_key.startswith(p) for p in THREAT_EVENT_KEYS)

    # ── Device Statistics (Integrations API v1 / Network 10.x+) ─────────

    def get_device_statistics(self, device_id: str) -> Optional[Dict[str, Any]]:
        """
        Obtém estatísticas detalhadas de um dispositivo UniFi.

        Prioridade:
          1. Integrations API v1  → /proxy/network/integrations/v1/sites/{site}/devices/{id}/statistics/latest
             Requer API Key. Retorna: uptimeSec, cpuUtilizationPct, memoryUtilizationPct,
             loadAverage1/5/15Min, interfaces.radios[].frequencyGHz/txRetriesPct
          2. Legacy v1            → /proxy/network/api/s/{site}/stat/device/{id}
             Funciona com autenticação por cookie.
        """
        # Tentativa via Integrations API (requer api_key ou sessão com permissão)
        if self._use_api_key:
            result = self._request_integrations(f"/devices/{device_id}/statistics/latest")
            if result is not None:
                # Integrations API pode retornar dict direto ou lista com 1 elemento
                return result if isinstance(result, dict) else (result[0] if result else None)

        # Fallback: endpoint legado v1
        result = self._request("GET", f"/stat/device/{device_id}")
        return result if isinstance(result, dict) else None

    def get_all_devices_statistics(self) -> List[Dict[str, Any]]:
        """
        Obtém estatísticas para TODOS os dispositivos adotados.

        Prioridade:
          1. Integrations API v1  → /proxy/network/integrations/v1/sites/{site}/devices
             Quando API Key configurada.
          2. Legacy v1            → /proxy/network/api/s/{site}/stat/device
             Fallback para firmware antigo ou autenticação por cookie.
        """
        if self._use_api_key:
            result = self._request_integrations("/devices")
            if result is not None:
                return result if isinstance(result, list) else []

        result = self._request("GET", "/stat/device")
        return result if isinstance(result, list) else []

    # ── Network Statistics (Integrations API v1 / Network 10.x+) ────────

    def get_networks(self) -> List[Dict[str, Any]]:
        """
        Obtém informações sobre todas as redes configuradas.

        Prioridade:
          1. Integrations API v1  → /proxy/network/integrations/v1/sites/{site}/networks
             Quando API Key configurada. Retorna: name, ipSubnet, numClients,
             upBytes, downBytes, upBytesRate, downBytesRate
          2. Legacy v1            → /proxy/network/api/s/{site}/rest/networkconf
             Fallback — retorna apenas configuração, sem métricas de tráfego.
        """
        if self._use_api_key:
            result = self._request_integrations("/networks")
            if result is not None:
                return result if isinstance(result, list) else []

        result = self._request("GET", "/rest/networkconf")
        return result if isinstance(result, list) else []

    def get_network_details(self, network_id: str) -> Optional[Dict[str, Any]]:
        """
        Obtém detalhes de uma rede específica.

        Prioridade:
          1. Integrations API v1  → /proxy/network/integrations/v1/sites/{site}/networks/{id}
          2. Legacy v1            → /proxy/network/api/s/{site}/rest/networkconf/{id}
        """
        if self._use_api_key:
            result = self._request_integrations(f"/networks/{network_id}")
            if result is not None:
                return result if isinstance(result, dict) else None

        return self._request("GET", f"/rest/networkconf/{network_id}")

    # ── Device Health & Performance ────────────────────────────────────

    def get_device_uptime(self, device_id: str) -> Optional[int]:
        """
        Retorna o uptime em segundos de um dispositivo.
        """
        stats = self.get_device_statistics(device_id)
        if stats and isinstance(stats, dict):
            return stats.get("uptimeSec")
        return None

    def get_device_load(self, device_id: str) -> Optional[Dict[str, float]]:
        """
        Retorna a carga média do dispositivo (1, 5, 15 min).
        """
        stats = self.get_device_statistics(device_id)
        if stats and isinstance(stats, dict):
            return {
                "load_1min": stats.get("loadAverage1Min"),
                "load_5min": stats.get("loadAverage5Min"),
                "load_15min": stats.get("loadAverage15Min"),
            }
        return None

    def get_device_resource_utilization(self, device_id: str) -> Optional[Dict[str, float]]:
        """
        Retorna utilização de CPU e memória do dispositivo.
        """
        stats = self.get_device_statistics(device_id)
        if stats and isinstance(stats, dict):
            return {
                "cpu_pct": stats.get("cpuUtilizationPct"),
                "memory_pct": stats.get("memoryUtilizationPct"),
            }
        return None

    def get_device_radio_quality(self, device_id: str) -> Optional[Dict[str, Any]]:
        """
        Retorna qualidade de rádio (TX retries %) e frequências por banda.
        """
        stats = self.get_device_statistics(device_id)
        if stats and isinstance(stats, dict):
            interfaces = stats.get("interfaces", {})
            if isinstance(interfaces, dict):
                radios = interfaces.get("radios", [])
                if isinstance(radios, list):
                    return {
                        "radios": [
                            {
                                "frequency_ghz": r.get("frequencyGHz"),
                                "tx_retries_pct": r.get("txRetriesPct"),
                            }
                            for r in radios
                        ]
                    }
        return None

    @staticmethod
    def infer_category_from_text(text: str) -> Optional[str]:
        lower = text.lower()
        for keyword, category in APP_CATEGORY_MAP.items():
            if keyword in lower:
                return category
        return None
