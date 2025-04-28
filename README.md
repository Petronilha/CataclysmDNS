# CataclysmDNS

**CataclysmDNS** é uma ferramenta de pentest DNS modular e extensível, desenvolvida em Python, que permite executar diversas atividades de reconhecimento, exploração e monitoramento de ambientes DNS de forma ágil e configurável.

---

## Índice

- [Funcionalidades](#funcionalidades)
- [Arquitetura e Módulos](#arquitetura-e-módulos)
- [Pré-requisitos](#pré-requisitos)
- [Instalação](#instalação)
  - [Modo Desenvolvimento (editable)](#modo-desenvolvimento-editable)
  - [Instalação Padrão](#instalação-padrão)
- [Uso](#uso)
- [Configuração do Ambiente (.env)](#configuração-do-ambiente-env)
- [Estrutura de Diretórios](#estrutura-de-diretórios)
- [Testes](#testes)
- [Contribuição](#contribuição)
- [Licença](#licença)

---

## Funcionalidades

- **Enumeração de Subdomínios**: pesquisa assíncrona de subdomínios com suporte a múltiplos tipos de registros (A, AAAA, MX, TXT, PTR), geração automática de permutações e detecção de wildcard DNS.
- **Brute-force de Subdomínios**: força-bruta usando wordlists customizáveis.
- **Transferência de Zona (AXFR)**: testa e extrai zona DNS em servidores autoritativos.
- **Verificação DNSSEC**: identifica se o domínio está protegido por DNSSEC.
- **Monitoramento de Registros**: captura snapshots e detecta mudanças em intervalos configuráveis.
- **Reconhecimento Passivo**: consulta fontes externas (VirusTotal, URLScan, DNSDumpster, AlienVault) para enriquecer a lista de subdomínios.
- **Detecção de Subdomain Takeover**: analisa configurações que podem levar ao takeover de subdomínios.
- **Caching de Resultados**: diversos níveis de cache para otimizar consultas repetidas.
- **Controle de Fluxo (Rate Limiting)**: gerencia volume de requisições para evitar bloqueios.
- **Logging Avançado**: logs estruturados em console e em arquivos com rotação e limpeza automática.

---

## Arquitetura e Módulos

- **cli.py**: ponto de entrada Typer, define os comandos (`enum`, `brute`, `zone-transfer`, `dnssec`, `monitor-dns`, `passive`, `takeover`, etc.).
- **config.py**: carrega variáveis de ambiente via `.env` (`API_KEYS`, timeouts, retries).
- **core/**: implementa a lógica principal:
  - `resolver.py` e `resolver_core.py`: enumeração básica e aprimorada de DNS.
  - `resolver_enhanced.py`: lógica avançada com retries e métricas.
  - `brute_force.py`: brute-force de subdomínios.
  - `zone_transfer.py`: AXFR.
  - `dnssec_checker.py`: DNSSEC.
  - `monitoring.py`: monitoramento contínuo.
  - `passive_recon.py`: reconhecimento passivo integrado a várias APIs.
  - `takeover_detector.py`: detecta vulnerabilidades de takeover.
  - `cache_*`: gerência de cache de resultados.
  - `rate_limiter.py`: controle de taxas.
  - `exceptions.py`: definições de erros customizados.

- **utils/**: funcionalidades auxiliares:
  - `enhanced_logger.py`, `logger.py`, `logger_config.py`: configuração de logging.
  - `retry_handler.py`: lógica de retry/backoff.
  - `wordlist_loader.py`: carregamento de wordlists.
  - `log_cleaner.py`: limpeza de arquivos de log antigos.

- **wordlists/**: modelos de wordlists de subdomínios.
- **tests/**: testes unitários para resolveres e demais componentes.

---

## Pré-requisitos

- Python 3.8+
- pip 21+
- Internet (para reconhecimento passivo)

---

## Instalação

### Modo Desenvolvimento (editable)

Permite atualizar com `git pull` sem reinstalar:

```bash
git clone https://github.com/SeuUsuario/CataclysmDNS.git
cd CataclysmDNS
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip setuptools wheel
pip install -e .
```

### Instalação Padrão

Instala como pacote estático:

```bash
git clone https://github.com/SeuUsuario/CataclysmDNS.git
cd CataclysmDNS
python3 -m venv venv        # opcional, mas recomendado
source venv/bin/activate
pip install --upgrade pip
pip install .
```

Após isso, o comando `cataclysm` estará disponível globalmente.

---

## Uso

```bash
# Enumeração básica + wildcard
echo ▶️ cataclysm enum --domain example.com

# Força-bruta de subdomínios
cataclysm brute --domain example.com --wordlist wordlists/subdomains.txt

# Teste de transferência de zona
echo ▶️ cataclysm zone-transfer --domain example.com --nameserver ns1.example.com

# Verificação DNSSEC
cataclysm dnssec --domain example.com

# Monitorar mudanças em A
cataclysm monitor-dns --domain example.com --interval 600

# Reconhecimento passivo (API keys devem estar em .env)
cataclysm passive --domain example.com

# Check subdomain takeover
cataclysm takeover --domain example.com
```

Use `cataclysm --help` ou `cataclysm <comando> --help` para ver opções e flags.

---

## Configuração do Ambiente (.env)

Crie um arquivo `.env` na raiz com suas chaves de API:

```env
VIRUSTOTAL_API_KEY=seu_token
URLSCAN_API_KEY=seu_token
DNSDUMPSTER_API_KEY=seu_token
ALIENVAULT_API_KEY=seu_token
TIMEOUT=30
MAX_RETRIES=3
```

---

## Estrutura de Diretórios

```text
CataclysmDNS/
├── cli.py
├── config.py
├── setup.py
├── requirements.txt
├── README.md
├── .gitignore
├── wordlists/
│   ├── subdomains.txt
│   └── exemplo.txt
├── core/
│   ├── __init__.py
│   ├── brute_force.py
│   ├── cache_base.py
│   ├── cache_config.py
│   ├── cache_manager.py
│   ├── cache_types.py
│   ├── dnssec_checker.py
│   ├── exceptions.py
│   ├── monitoring.py
│   ├── passive_recon.py
│   ├── passive_recon_cached.py
│   ├── proxy_manager.py
│   ├── rate_limiter.py
│   ├── resolver.py
│   ├── resolver_cached.py
│   ├── resolver_core.py
│   ├── resolver_enhanced.py
│   ├── takeover_detector.py
│   └── zone_transfer.py
├── utils/
│   ├── __init__.py
│   ├── enhanced_logger.py
│   ├── log_cleaner.py
│   ├── logger.py
│   ├── logger_config.py
│   ├── retry_handler.py
│   └── wordlist_loader.py
└── tests/
    └── test_resolver.py
```

---

## Testes

Execute a suíte de testes com:

```bash
pytest
```

---

## Contribuição

1. Fork do repositório
2. Crie uma branch: `git checkout -b feature/nome-da-feature`
3. Commit suas alterações: `git commit -m 'Adiciona feature X'`
4. Push na branch: `git push origin feature/nome-da-feature`
5. Abra um Pull Request

---

## Licença

Este projeto está licenciado sob a [MIT License](LICENSE).

