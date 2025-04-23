# CataclysmDNS

**CataclysmDNS** é uma ferramenta de pentest DNS modular e extensível, desenvolvida em Python para realizar enumeração, exploração e monitoramento de configurações DNS de forma avançada e personalizável.

---

## Funcionalidades Principais

- **Enumeração de Subdomínios**: varredura assíncrona de subdomínios com suporte a múltiplos tipos de registro (A, AAAA, MX, TXT, PTR) e geração de permutações.
- **Detecção de Wildcard DNS**: identifica configurações de wildcard para filtrar falsos positivos.
- **Transferência de Zona (AXFR)**: tenta extrair toda a zona DNS de servidores autoritativos.
- **Brute Force de Subdomínios**: utiliza wordlists customizadas (ex.: SecLists, Assetnote) para descobrir subdomínios adicionais.
- **Verificação de DNSSEC**: checa se o domínio possui DNSSEC habilitado e avalia a integridade da cadeia de assinatura.
- **Monitoramento de Alterações**: monitora periodicamente mudanças em registros DNS e gera alertas.

---

## Requisitos

- Python 3.10+
- Sistema operacional: Linux, macOS ou Windows

### Dependências

Todas as dependências estão listadas em `requirements.txt`:

```txt
dnspython>=2.4.2
aiohttp>=3.8.5
typer>=0.9.0
rich>=14.0.0
```

---

## Instalação

```bash
git clone https://github.com/seu-usuario/CataclysmDNS.git
cd CataclysmDNS
python3 -m venv venv
source venv/bin/activate    # macOS/Linux
# venv\Scripts\activate   # Windows
pip install -r requirements.txt
```

---

## Estrutura do Projeto

```
cataclysm_dns/
├── cli.py             # Interface de linha de comando (Typer)
├── requirements.txt   # Dependências do projeto
├── wordlists/         # Wordlists de subdomínios (ex: subdomains.txt)
├── core/              # Módulos principais
│   ├── resolver.py    # Enumeração de subdomínios e detect wildcard
│   ├── zone_transfer.py # Transferência de zona (AXFR)
│   ├── brute_force.py # Brute force baseado em wordlists
│   ├── dnssec_checker.py # Verificação de DNSSEC
│   └── monitoring.py  # Monitoramento de alterações de DNS
└── utils/             # Utilitários auxiliares
    ├── logger.py      # Configuração de logs com Rich
    └── wordlist_loader.py # Carregamento de arquivos de wordlist
```

---

## Uso

Todos os comandos utilizam o script `cli.py`. Veja abaixo os principais:

### `enum`

Enumera subdomínios, resolve múltiplos tipos de registro e detecta wildcard.

```bash
python cli.py enum \
  --domain example.com \
  --wordlist wordlists/subdomains.txt \
  --nameserver 1.1.1.1 \
  --workers 30
```

**Opções**:

- `--domain` (obrigatório): domínio alvo.
- `--wordlist`: caminho para wordlist de subdomínios (padrão: `wordlists/subdomains.txt`).
- `--nameserver`: servidor DNS para override (opcional).
- `--workers`: número de tarefas concorrentes (padrão: 20).

### `resolve`

Resolve registros DNS de forma pontual (sync).

```bash
python cli.py resolve --name dev.example.com --record A
```

### `zone-transfer`

Tenta transferência de zona (AXFR) em servidor autoritativo.

```bash
python cli.py zone-transfer \
  --domain example.com \
  --nameserver ns1.example.com
```

### `brute`

Realiza brute force de subdomínios usando uma wordlist.

```bash
python cli.py brute \
  --domain example.com \
  --wordlist wordlists/subdomains.txt \
  --workers 100
```

### `dnssec`

Verifica se o domínio tem DNSSEC habilitado.

```bash
python cli.py dnssec --domain example.com
```

### `monitor-dns`

Monitora mudanças em registros DNS em intervalos regulares.

```bash
python cli.py monitor-dns \
  --domain example.com \
  --interval 600   # a cada 10 minutos
```

---

## Wordlists

Sugestões de wordlists:

- [SecLists - SecLists/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)
- Assetnote [best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/) (via CDN)

Coloque seus arquivos `.txt` em `wordlists/` e atualize o parâmetro `--wordlist`.

---

## Contribuições

1. Faça um fork do repositório
2. Crie uma branch: `git checkout -b feature/nova-funcionalidade`
3. Commit suas mudanças: `git commit -m 'Adiciona nova feature'`
4. Push para a branch: `git push origin feature/nova-funcionalidade`
5. Abra um Pull Request

---

## Licença

MIT License © Petronilha