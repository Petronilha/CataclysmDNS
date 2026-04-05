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
- **Transferência de Zona (AXFR)**: testa e extrai zona DNS em servidores autoritativos.

---

## Arquitetura e Módulos

- **cli.py**: ponto de entrada Typer, define os comandos (`enum`, `zone-transfer`,).
- **config.py**: carrega variáveis de ambiente via `.env` (`API_KEYS`, timeouts, retries).
- **core/**: implementa a lógica principal:
  - `resolver.py` e `resolver_core.py`: enumeração básica e aprimorada de DNS.
  - `resolver_enhanced.py`: lógica avançada com retries e métricas.
  - `brute_force.py`: brute-force de subdomínios.
  - `zone_transfer.py`: AXFR.
  - `passive_recon.py`: reconhecimento passivo integrado a várias APIs.
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

---

## Instalação

### Modo Desenvolvimento (editable)

Permite atualizar com `git pull` sem reinstalar:

```bash
git clone https://github.com/SeuUsuario/CataclysmDNS.git
cd CataclysmDNS
python3 -m venv venv
source venv/bin/activate
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

# Teste de transferência de zona
echo ▶️ cataclysm zone-transfer --domain example.com --nameserver ns1.example.com

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
├── pyproject.toml
├── README.md
├── .gitignore
├── wordlists/
│   ├── subdomains.txt
│   └── exemplo.txt
├── core/
│   ├── __init__.py
│   ├── brute_force.py
│   ├── exceptions.py
│   ├── passive_recon.py
│   ├── rate_limiter.py
│   ├── resolver.py
│   ├── resolver_core.py
│   ├── resolver_enhanced.py
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

## Licença

Este projeto está licenciado sob a [MIT License](LICENSE).

