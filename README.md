# UniFi Intelligence Hub 🛡️

Sistema de monitoramento e auditoria avançada para Ubiquiti Dream Machine Pro (UDM-Pro).

> **Diferencial:** O painel nativo do UDM-Pro só mostra o "agora". Este sistema guarda **todo o histórico para sempre**, identifica infratores pelo nome, detecta burst de acessos suspeitos e gera relatórios PDF gerenciais.

---

## Arquitetura

```
unifi-intelligence-hub/
├── src/
│   ├── api_client.py         # Cliente HTTP nativo da UniFi API (UDM-Pro)
│   ├── collector.py          # Daemon de coleta — polling da API
│   ├── database_manager.py   # Schema SQLAlchemy + todas as queries do dashboard
│   ├── models.py             # ORM models (Client, WANStatus, FirewallBlock, Threat, DPITraffic)
│   └── audit_engine.py       # Detecção de dispositivos suspeitos + classificação de eventos
├── ui/
│   ├── app.py                # App Streamlit principal (navegação + roteamento)
│   └── components/
│       ├── overview.py       # Página: Visão Geral (WAN, KPIs, gauge de uptime)
│       ├── violators.py      # Página: Painel do Infrator (ranking + feed de bloqueios)
│       ├── security.py       # Página: Segurança (timeline IPS, dispositivos suspeitos)
│       └── reports.py        # Página: Relatórios (PDF gerencial + CSV exports)
├── data/                     # Banco SQLite (gerado automaticamente)
├── .env.example              # Template de configuração
├── requirements.txt
└── run.py                    # CLI unificado
```

---

## Pré-requisitos

- Python 3.10+
- Acesso de rede ao UDM-Pro (mesma LAN ou VPN)
- Usuário "View Only" criado no UDM-Pro

---

## Instalação Rápida

```bash
# 1. Clone o repositório
git clone <repo-url> unifi-intelligence-hub
cd unifi-intelligence-hub

# 2. Crie um ambiente virtual
python -m venv .venv
source .venv/bin/activate          # Linux/macOS
.venv\Scripts\activate             # Windows

# 3. Instale as dependências
pip install -r requirements.txt

# 4. Configure as credenciais
cp .env.example .env
# Edite .env com seu editor preferido:
#   UNIFI_HOST, UNIFI_USERNAME, UNIFI_PASSWORD

# 5. Inicialize o banco de dados
python run.py init-db
```

---

## Configuração do Usuário de API no UDM-Pro

1. Acesse o UniFi Dashboard → **Settings → Admins & Users**
2. Clique em **Add Admin**
3. Defina:
   - **Role:** `View Only`
   - **Account Type:** `Local Access Only`
4. Guarde o usuário e senha no seu `.env`

> ⚠️ **Nunca use credenciais de super-admin no script.** Uma conta `View Only` é suficiente para leitura de todos os dados e limita o raio de blast caso as credenciais vazem.

---

## Uso

### Coletor de Dados (daemon)
```bash
# Roda indefinidamente, coletando a cada POLL_INTERVAL_SECONDS (padrão: 60s)
python run.py collect
```

### Coleta única (debug / teste)
```bash
python run.py collect-once
```

### Dashboard Web
```bash
# Em outro terminal (pode rodar simultaneamente com o coletor)
python run.py ui
# Acesse: http://localhost:8501
```

### Produção (background)
```bash
# Coletor em background
nohup python run.py collect > data/collector.log 2>&1 &

# Dashboard
nohup python run.py ui > data/ui.log 2>&1 &
```

---

## Banco de Dados

| Tabela            | Conteúdo                                         |
|-------------------|--------------------------------------------------|
| `clients`         | Registro de dispositivos (MAC, nome, IP, vendor) |
| `wan_status`      | Snapshots históricos de uptime e latência WAN    |
| `firewall_blocks` | Todos os bloqueios de firewall/traffic rules      |
| `threats`         | Eventos IPS/IDS e Threat Management              |
| `dpi_traffic`     | Snapshots de tráfego DPI por cliente             |
| `vpn_status`      | Status histórico de túneis VPN                   |

**Deduplicação:** cada evento é identificado pelo `_id` único retornado pela API UniFi, garantindo que reinicializações do coletor nunca dupliquem registros.

---

## Lógica de Auditoria

### Detecção de Dispositivos Suspeitos
- Threshold configurável via `SUSPICIOUS_BLOCKS_THRESHOLD` (padrão: 5 bloqueios/minuto)
- O AuditEngine roda após cada ciclo de coleta
- Dispositivos flagados aparecem com alerta vermelho no painel de Segurança

### Classificação de Bloqueios
| Tipo               | Critério                                           |
|--------------------|---------------------------------------------------|
| `traffic_rule`     | Bloqueio por categoria DPI / aplicação             |
| `firewall_rule`    | Bloqueio por IP de destino / porta                 |

### Resolução de Nomes
O collector cruza o MAC do evento com a tabela `clients` para exibir o **nome amigável** configurado no UniFi em vez do endereço MAC bruto.

---

## Configuração `.env`

| Variável                      | Padrão                          | Descrição                              |
|-------------------------------|---------------------------------|----------------------------------------|
| `UNIFI_HOST`                  | —                               | URL do UDM-Pro (ex: `https://192.168.1.1`) |
| `UNIFI_USERNAME`              | —                               | Usuário View Only                      |
| `UNIFI_PASSWORD`              | —                               | Senha                                  |
| `UNIFI_SITE`                  | `default`                       | Site ID do UniFi Network               |
| `UNIFI_VERIFY_SSL`            | `false`                         | Validar certificado SSL                |
| `DB_URL`                      | `sqlite:///./data/unifi_hub.db` | URL do banco (SQLAlchemy)              |
| `POLL_INTERVAL_SECONDS`       | `60`                            | Intervalo de coleta (segundos)         |
| `EVENTS_FETCH_LIMIT`          | `3000`                          | Eventos por ciclo de coleta            |
| `SUSPICIOUS_BLOCKS_THRESHOLD` | `5`                             | Bloqueios/minuto para marcar suspeito  |
| `LOG_LEVEL`                   | `INFO`                          | DEBUG, INFO, WARNING, ERROR            |

---

## Hardware Recomendado

| Opção              | Especificação mínima             | Custo     |
|--------------------|----------------------------------|-----------|
| Raspberry Pi 5     | 4 GB RAM, SSD via USB            | ~US$ 80   |
| Beelink Mini PC    | Intel N100, 8 GB RAM, 256 GB SSD | ~US$ 150  |
| Servidor Docker    | Qualquer host Linux 24/7         | Variável  |

---

## Suporte a PostgreSQL

1. Instale o driver: `pip install psycopg2-binary`
2. No `.env`: `DB_URL=postgresql://usuario:senha@host:5432/unifi_hub`

---

## Roadmap / Próximas Features

- [ ] Alertas por e-mail / Telegram quando dispositivo é marcado suspeito
- [ ] Integração com Grafana via datasource PostgreSQL
- [ ] Suporte a múltiplos sites UniFi
- [ ] Dashboard em modo quiosque (auto-refresh via `st_autorefresh`)
- [ ] Detecção de port-scanning (múltiplos dst_ports em curto intervalo)
