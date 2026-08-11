<h1 align="center">vamp-graphql-audit</h1>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.11%2B-blue?logo=python&logoColor=white" alt="Python 3.11+"/>
  <img src="https://img.shields.io/badge/platform-linux%20%7C%20macOS-lightgrey" alt="Platform"/>
  <img src="https://img.shields.io/badge/async-aiohttp-green" alt="aiohttp"/>
  <img src="https://img.shields.io/badge/VampSecure-Labs-magenta" alt="VampSecure Labs"/>
</p>

## Overview

`vamp-graphql-audit` is a DAST (Dynamic Application Security Testing) tool specialized in GraphQL APIs. It performs six sequential audit phases covering the most critical GraphQL-specific attack vectors: introspection abuse, broken object-level authorization (BOLA/IDOR), rate-limit bypass via alias abuse, deep nesting DoS, information disclosure via field suggestions, injection testing (SQLi, NoSQLi, SSTI, XSS), and subscription/mutation security analysis.

It generates professional reports in rich console output, JSON, and a self-contained HTML dark-theme document — ready to attach to a pentest engagement.

## Features

- **Phase 1 — Introspection & Recon**: detects enabled introspection (CRITICAL), extracts full schema (queries, mutations, subscriptions, types), identifies sensitive field names (password, token, key, email…), checks for verbose error messages with stack traces or file paths, and fingerprints directives to identify framework.
- **Phase 2 — Authorization Testing (BOLA/IDOR)**: fuzzes ID arguments (1, 2, 3, 999, -1, "admin", null…) on every query with an ID-shaped argument; flags CRITICAL when different IDs return non-null data without apparent ownership checks.
- **Phase 3 — Rate Limiting & DoS**: alias abuse with 100 aliases in one HTTP request (HIGH), deeply-nested query with configurable `--depth` (HIGH if > 5s or timeout), batch query abuse via JSON array payload (HIGH).
- **Phase 4 — Information Disclosure**: confirms active GraphQL endpoint via `__typename`, detects field suggestions that leak schema even with introspection disabled (MEDIUM), checks for verbose variable-error messages, inspects non-standard directives.
- **Phase 5 — Injection Testing**: SQL injection via error-response analysis, NoSQL operator injection via GraphQL variables, SSTI detection by evaluating `{{7*7}}` markers in response, Reflected XSS via GraphQL string arguments.
- **Phase 6 — Subscription & Mutation Security**: HTTP vs HTTPS check, subscription authentication advisory, rate-limiting absence on auth mutations (login, register…), credential-change mutations without current-password confirmation, token return types over unencrypted HTTP.

## Requirements

- Python 3.11 or later
- `aiohttp >= 3.9.0`
- `rich >= 13.7.0`

```bash
pip install -r requirements.txt
```

## Usage

```bash
# Auditoría básica
python3 vamp_graphql_audit.py --target https://api.ejemplo.com/graphql

# Con cabecera de autenticación
python3 vamp_graphql_audit.py \
  --target https://api.ejemplo.com/graphql \
  --header "Authorization: Bearer eyJhbGc..."

# Múltiples cabeceras + exportar informe
python3 vamp_graphql_audit.py \
  --target https://api.ejemplo.com/graphql \
  --header "Authorization: Bearer TOKEN" \
  --header "X-Tenant-Id: acme" \
  --json informe.json \
  --html informe.html

# Controlar profundidad del test DoS de nesting
python3 vamp_graphql_audit.py \
  --target https://api.ejemplo.com/graphql \
  --depth 12

# Timeout por petición en segundos (default: 30)
python3 vamp_graphql_audit.py \
  --target https://api.ejemplo.com/graphql \
  --timeout 60
```

## Exit Codes

| Code | Significado |
|------|-------------|
| `0`  | Auditoría limpia — sin hallazgos CRITICAL ni HIGH |
| `1`  | Al menos un hallazgo CRITICAL o HIGH |
| `2`  | Error de ejecución (red, parámetros inválidos, interrupción) |

## Output

- **Console**: banner ASCII + progreso en tiempo real por fase + tabla resumen de findings ordenados por severidad.
- **JSON** (`--json FILE`): objeto con metadata, resumen por severidad, schema descubierto y array completo de findings.
- **HTML** (`--html FILE`): informe auto-contenido dark-theme con resumen ejecutivo, tabla de findings con evidencias expandibles y panel del schema descubierto.

## Disclaimer

Esta herramienta es exclusiva para auditorías de seguridad autorizadas. El uso contra sistemas sin autorización escrita del propietario es ilegal. VampSecure Studios no asume responsabilidad por usos indebidos.
