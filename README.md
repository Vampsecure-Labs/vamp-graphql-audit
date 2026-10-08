<!-- © VampSecure Studios — VampSecure Labs Security Research Division -->
<h1 align="center">vamp-graphql-audit</h1>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.11%2B-blue?logo=python&logoColor=white" alt="Python 3.11+"/>
  <img src="https://img.shields.io/badge/platform-linux%20%7C%20macOS-lightgrey" alt="Platform"/>
  <img src="https://img.shields.io/badge/async-aiohttp-green" alt="aiohttp"/>
  <img src="https://img.shields.io/badge/VampSecure-Labs-magenta" alt="VampSecure Labs"/>
  <img src="https://github.com/Vampsecure-Labs/vamp-graphql-audit/actions/workflows/ci.yml/badge.svg" alt="CI"/>
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

## Instalación

```bash
pip install vamp-graphql-audit
# o con Homebrew:
brew install vampsecure-labs/labs/vamp-graphql-audit
```

## Requisitos

- Python 3.11+
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

## Sample Output

```text
vamp-graphql-audit v1.4.0 · target: https://api.example.com/graphql
─────────────────────────────────────────────────────────────────────────
Phase 1 · Introspection & Recon
  [CRITICAL] GRAPHQL-001  Introspection enabled — full schema exposed
             46 types · 18 queries · 7 mutations · 2 subscriptions
             Sensitive fields found: email, passwordHash, authToken, apiKey

Phase 2 · Authorization (BOLA/IDOR)
  [CRITICAL] GRAPHQL-002  BOLA/IDOR on query getUser(id: 2) — returns user data
             id=1 → {id:1,email:"admin@example.com",role:"admin"}
             id=2 → {id:2,email:"user@example.com",role:"user"}
             No ownership check detected across 5 tested IDs

Phase 3 · Rate Limiting & DoS
  [HIGH]     GRAPHQL-003  Alias abuse: 100 aliases resolved in 1 request (312ms)
             No rate-limit or alias-count enforcement detected
  [HIGH]     GRAPHQL-004  Deeply nested query (depth=10) resolved in 8.4s
             Threshold exceeded: > 5s  — no query depth limit configured

Phase 4 · Information Disclosure
  [MEDIUM]   GRAPHQL-005  Field suggestions leak schema with introspection disabled
             Suggestion: "Did you mean 'passwordHash'?" on typo 'passwordHas'

Phase 5 · Injection Testing
  [MEDIUM]   GRAPHQL-006  Error message reveals SQL query fragment
             Fragment: "syntax error at or near 'FROM users WHERE id='"

Phase 6 · Subscription & Mutation Security
  [HIGH]     GRAPHQL-007  Auth mutation 'login' has no rate-limit (200 req/s tested)
  [LOW]      GRAPHQL-008  Subscription endpoint active over HTTP (not HTTPS)

┌──────────────────────┬────────┬──────┐
│ Severity             │ Count  │      │
├──────────────────────┼────────┼──────┤
│ CRITICAL             │   2    │ ████ │
│ HIGH                 │   3    │ ███  │
│ MEDIUM               │   2    │ ██   │
│ LOW                  │   1    │ █    │
└──────────────────────┴────────┴──────┘
8 findings · exit 1
```

---

## Why vamp-graphql-audit vs. InQL · Clairvoyance · OWASP ZAP GraphQL addon

| Característica | vamp-graphql-audit | InQL | Clairvoyance | ZAP GraphQL addon |
|---|---|---|---|---|
| BOLA/IDOR testing automatizado | ✅ | ❌ | ❌ | ❌ |
| DoS: alias abuse + deep nesting | ✅ | ❌ | ❌ | ⚠️ parcial |
| Injection testing (SQLi/NoSQLi/SSTI/XSS) | ✅ | ❌ | ❌ | ✅ |
| Field suggestion leak detection | ✅ | ❌ | ✅ | ❌ |
| Mutation security (rate-limit, credential flow) | ✅ | ❌ | ❌ | ⚠️ parcial |
| Informe HTML autónomo dark-theme | ✅ | ❌ | ❌ | ✅ (requiere ZAP) |
| Sin dependencias externas salvo aiohttp | ✅ | ⚠️ Burp required | ✅ | ❌ requiere ZAP |
| Exit codes CI/CD | ✅ 0/1/2 | ❌ | ❌ | ❌ |

- **Cobertura end-to-end en 6 fases**: el único tool que combina reconocimiento, BOLA, DoS, información, inyección y mutaciones en un solo binario sin dependencias externas de tipo proxy/IDE.
- **BOLA/IDOR automatizado**: InQL y Clairvoyance solo mapean el schema; vamp-graphql-audit fuzz-ea los argumentos de tipo ID en cada query y detecta acceso cruzado de forma autónoma.
- **Alias abuse y deep nesting**: tests de DoS basados en RFC de GraphQL — sin necesidad de configurar Burp o ZAP.
- **Diseñado para CI/CD**: exit code 1 en CRITICAL/HIGH bloquea el pipeline antes de desplegar; los otros tools carecen de esta integración nativa.

---

## Check Coverage

| Check ID | Description | Standard | Severity |
|----------|-------------|----------|----------|
| GRAPHQL-001 | Introspection enabled — full schema exposed to unauthenticated requests | OWASP API9:2023 / GraphQL Security BP §1 | CRITICAL |
| GRAPHQL-002 | BOLA/IDOR — cross-user data accessible by ID fuzzing | OWASP API1:2023 (BOLA) | CRITICAL |
| GRAPHQL-003 | Alias abuse — 100 aliases resolved in a single HTTP request | OWASP API4:2023 (Unrestricted Resource Consumption) | HIGH |
| GRAPHQL-004 | Deep nesting DoS — query depth > 5 levels resolved without timeout | OWASP API4:2023 / GraphQL Security BP §4 | HIGH |
| GRAPHQL-005 | Batch query abuse — JSON array payload accepted without rate limit | OWASP API4:2023 | HIGH |
| GRAPHQL-006 | Auth mutation (login/register) without rate-limit enforcement | OWASP API4:2023 / OWASP API2:2023 | HIGH |
| GRAPHQL-007 | Field suggestion leak — schema enumerable despite introspection disabled | OWASP API9:2023 / GraphQL Security BP §2 | MEDIUM |
| GRAPHQL-008 | Verbose error messages leak stack traces or file paths | OWASP API9:2023 | MEDIUM |
| GRAPHQL-009 | SQL injection via GraphQL string argument — error-based detection | OWASP API8:2023 (Security Misconfiguration) | MEDIUM |
| GRAPHQL-010 | NoSQL operator injection via GraphQL variables ($where, $gt) | OWASP API8:2023 | MEDIUM |
| GRAPHQL-011 | SSTI detection — `{{7*7}}` marker evaluated in response | OWASP API8:2023 | HIGH |
| GRAPHQL-012 | Credential-change mutation without current-password confirmation | OWASP API2:2023 (Broken Authentication) | HIGH |
| GRAPHQL-013 | Token returned over unencrypted HTTP endpoint | OWASP API7:2023 (Server-Side Request Forgery) | HIGH |
| GRAPHQL-014 | Subscription endpoint active without authentication advisory | GraphQL Security BP §6 | LOW |

---

## Disclaimer

Esta herramienta es exclusiva para auditorías de seguridad autorizadas. El uso contra sistemas sin autorización escrita del propietario es ilegal. VampSecure Studios no asume responsabilidad por usos indebidos.

---

## Versión
v1.4.0 — VampSecure Labs Security Research Division
