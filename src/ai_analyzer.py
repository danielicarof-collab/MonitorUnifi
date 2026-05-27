"""
AI threat analyzer — uses Claude API to assess current security posture.
Requires ANTHROPIC_API_KEY environment variable.
"""
from __future__ import annotations

import json
import os
from typing import Optional

import anthropic
from loguru import logger

_SYSTEM_PROMPT = """Você é um analista de segurança de redes especializado em ambientes UniFi.
Analise os dados de segurança fornecidos e retorne SOMENTE um JSON válido neste formato exato:
{
  "severidade": "crítica" | "alta" | "média" | "baixa",
  "nivel": "N4" | "N3" | "N2" | "N1",
  "confianca": <inteiro 0-100>,
  "resumo": "<análise em 1-2 frases>",
  "recomendacao": "<ação recomendada em 1 frase>"
}

Critérios:
- crítica/N4: comprometimento ativo, muitas ameaças críticas ou dispositivos suspeitos com burst de bloqueios
- alta/N3: ameaças IPS/IDS ativas, dispositivos suspeitos detectados, padrões de ataque visíveis
- média/N2: bloqueios moderados, alguns infratores ativos, possível reconhecimento
- baixa/N1: atividade normal, poucos bloqueios, sem ameaças críticas

Confiança: 0-100 refletindo qualidade/quantidade dos dados disponíveis."""


class ThreatAnalyzer:
    """Analyzes security posture using Claude API with prompt caching."""

    def __init__(self) -> None:
        api_key = os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            raise ValueError("ANTHROPIC_API_KEY não configurada")
        self._client = anthropic.Anthropic(api_key=api_key)

    def analyze(
        self,
        stats: dict,
        threat_count: int,
        suspicious_count: int,
        top_threats: list,
    ) -> Optional[dict]:
        """Return AI analysis dict or None on failure."""
        try:
            user_content = self._build_context(stats, threat_count, suspicious_count, top_threats)
            with self._client.messages.stream(
                model="claude-opus-4-7",
                max_tokens=512,
                system=[{
                    "type": "text",
                    "text": _SYSTEM_PROMPT,
                    "cache_control": {"type": "ephemeral"},
                }],
                messages=[{"role": "user", "content": user_content}],
            ) as stream:
                response = stream.get_final_message()

            text = next((b.text for b in response.content if b.type == "text"), "{}")
            result = json.loads(text)
            required = {"severidade", "nivel", "confianca", "resumo", "recomendacao"}
            if not required.issubset(result.keys()):
                return None
            return result
        except Exception as e:
            logger.debug("AI analysis error: {}", e)
            return None

    def _build_context(
        self,
        stats: dict,
        threat_count: int,
        suspicious_count: int,
        top_threats: list,
    ) -> str:
        lines = [
            "DADOS DE SEGURANÇA (últimas 24h):",
            f"- Bloqueios totais: {stats.get('total_blocks', 0)}",
            f"- Infratores únicos: {stats.get('unique_violators', 0)}",
            f"- Ameaças IPS/IDS: {threat_count}",
            f"- Dispositivos suspeitos: {suspicious_count}",
            f"- Dispositivos online: {stats.get('online_devices', 0)}",
        ]
        if top_threats:
            lines.append("\nÚLTIMAS AMEAÇAS:")
            for t in top_threats[:5]:
                sev   = t.get("severity", "?")
                ttype = t.get("threat_type", "?")
                src   = t.get("client_name") or "desconhecido"
                lines.append(f"  [{sev.upper()}] {ttype} — origem: {src}")
        return "\n".join(lines)
