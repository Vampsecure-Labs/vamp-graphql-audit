# © VampSecure Studios — VampSecure Labs Security Research Division
"""
vamp_graphql_audit.py — Auditor DAST de APIs GraphQL
=====================================================
© VampSecure Studios — VampSecure Labs Security Research Division

Herramienta de auditoría dinámica (DAST) especializada en APIs GraphQL.
Ejecuta seis fases de análisis: introspección, autorización, rate-limiting/DoS,
divulgación de información, inyecciones y seguridad de subscripciones/mutations.

Fases
-----
  1. Introspección y reconocimiento (schema completo, tipos sensibles)
  2. Authorization Testing (IDOR/BOLA por ID fuzzing)
  3. Rate Limiting & DoS (alias abuse, deep nesting, batch)
  4. Information Disclosure (field suggestions, errores verbosos)
  5. Injection Testing (SQLi, NoSQLi, SSTI, XSS via GraphQL)
  6. Subscription & Mutation Security

Uso básico
----------
  python3 vamp_graphql_audit.py --target https://api.ejemplo.com/graphql
  python3 vamp_graphql_audit.py --target URL --header "Authorization: Bearer TOKEN"
  python3 vamp_graphql_audit.py --target URL --json out.json --html informe.html
  python3 vamp_graphql_audit.py --target URL --depth 10

Dependencias
------------
  pip install aiohttp>=3.9.0 rich>=13.7.0

Exit codes
----------
  0  Sin findings críticos ni altos
  1  Al menos un finding CRITICAL o HIGH
  2  Error de ejecución (red, parámetros incorrectos…)
"""

# =============================================================================
# IMPORTACIONES
# =============================================================================

import argparse
import asyncio
import json
import re
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

try:
    import aiohttp
except ImportError:
    print("[ERROR] Instala aiohttp: pip install aiohttp>=3.9.0", file=sys.stderr)
    sys.exit(2)

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich import box
except ImportError:
    print("[ERROR] Instala rich: pip install rich>=13.7.0", file=sys.stderr)
    sys.exit(2)

# =============================================================================
# CONSTANTES Y METADATOS
# =============================================================================

TOOL_NAME  = "vamp-graphql-audit"
VERSION    = "1.1.0"
USER_AGENT = f"VampSecureLabs/{VERSION} ({TOOL_NAME})"

# Tiempo máximo (segundos) para considerar una query como DoS
DOS_TIMEOUT_THRESHOLD = 5.0

# Número de aliases para el ataque de rate-limit bypass
ALIAS_COUNT = 100

# Número de queries batch para la prueba DoS de batch
BATCH_QUERY_COUNT = 50

# Severidades reconocidas (en orden descendente de criticidad)
SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

# Paleta de colores Rich por severidad
SEV_COLOR: Dict[str, str] = {
    "CRITICAL": "bold red",
    "HIGH":     "bold orange3",
    "MEDIUM":   "bold yellow",
    "LOW":      "bold cyan",
    "INFO":     "bold white",
}

# Payloads de inyección SQL básica
SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "1; DROP TABLE users--",
    "' UNION SELECT NULL,NULL--",
    "admin'--",
]

# Payloads NoSQL injection
NOSQLI_PAYLOADS = [
    '{"$gt": ""}',
    '{"$regex": ".*"}',
    '{"$ne": null}',
    '{"$where": "1==1"}',
]

# Payloads SSTI (Server-Side Template Injection)
SSTI_PAYLOADS = [
    "{{7*7}}",
    "${7*7}",
    "#{7*7}",
    "<%= 7*7 %>",
    "{{config}}",
]

# Payload XSS básico
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert(1)",
]

# Nombres de campo que denotan información sensible
SENSITIVE_FIELD_NAMES = [
    "password", "passwd", "pwd", "secret", "token", "api_key", "apikey",
    "key", "email", "credit_card", "creditcard", "ssn", "hash", "salt",
    "private_key", "privatekey", "access_token", "refresh_token",
    "client_secret", "auth", "authorization", "session", "cookie",
]

# Nombres de mutations relacionadas con autenticación
AUTH_MUTATION_NAMES = [
    "login", "signin", "signup", "register", "authenticate", "auth",
    "createUser", "createAccount", "resetPassword", "changePassword",
    "updatePassword", "forgotPassword", "requestPasswordReset",
]

# Nombres de mutations de cambio de credenciales sin requerir password actual
DANGEROUS_MUTATION_NAMES = [
    "updateEmail", "changeEmail", "updatePassword", "changePassword",
    "resetPassword", "setPassword", "updateProfile",
]

# =============================================================================
# BANNER ASCII
# =============================================================================

BANNER = r"""
  ____   ____    _    __  __ ____  _____ ____ _   _ ____  _____   _        _    ____ ____
 \ \ / / _  |  / \  |  \/  |  _ \/ ____/ ___| | | |  _ \| ____| | |      / \  | __ ) ___|
  \ V / (_| | / _ \ | |\/| | |_) \___ \| |___| | | | |_) |  _|   | |     / _ \ |  _ \___ \
   | |  \__, |/ ___ \| |  | |  __/ ___) |___  | |_| |  _ <| |___  | |___ / ___ \| |_) |__) |
   |_|     /_/_/   \_|_|  |_|_|   |____/\____|\___/|_| \_|_____| |_____/_/   \_|____/____/
     by Antonio Hernandez "Belky" — VampSecure Studios · vamp-graphql-audit v1.1 · GraphQL Security Auditor
     ─────────────────────────────────────────────────────────────────────────────────────────
     USO EXCLUSIVO EN AUDITORÍAS AUTORIZADAS · El uso no autorizado es ilegal
"""

console = Console(highlight=False)

# =============================================================================
# DATACLASSES
# =============================================================================

@dataclass
class Finding:
    """Representa un hallazgo de seguridad detectado durante la auditoría."""
    tool:           str
    severity:       str                       # CRITICAL / HIGH / MEDIUM / LOW / INFO
    type:           str                       # Categoría del finding
    title:          str                       # Título corto descriptivo
    description:    str                       # Descripción detallada
    affected:       str                       # Recurso/endpoint/campo afectado
    recommendation: str                       # Medida de remediación recomendada
    evidence:       Optional[str] = None      # Payload o respuesta que evidencia el hallazgo
    phase:          int           = 0         # Fase de la auditoría que lo detectó

    def to_dict(self) -> Dict:
        """Serializa el finding a diccionario JSON-exportable."""
        return {
            "tool":           self.tool,
            "severity":       self.severity,
            "type":           self.type,
            "title":          self.title,
            "description":    self.description,
            "affected":       self.affected,
            "recommendation": self.recommendation,
            "evidence":       self.evidence,
            "phase":          self.phase,
        }


@dataclass
class SchemaInfo:
    """Resumen del schema GraphQL descubierto durante la introspección."""
    types:         List[str]       = field(default_factory=list)
    queries:       List[str]       = field(default_factory=list)
    mutations:     List[str]       = field(default_factory=list)
    subscriptions: List[str]       = field(default_factory=list)
    sensitive_fields: List[str]    = field(default_factory=list)
    raw_schema:    Optional[Dict]  = None


# =============================================================================
# QUERY DE INTROSPECCIÓN COMPLETA
# =============================================================================

INTROSPECTION_QUERY = """
{
  __schema {
    queryType  { name }
    mutationType { name }
    subscriptionType { name }
    types {
      name
      kind
      description
      fields(includeDeprecated: true) {
        name
        isDeprecated
        deprecationReason
        type {
          name
          kind
          ofType {
            name
            kind
            ofType {
              name
              kind
              ofType {
                name
                kind
              }
            }
          }
        }
        args {
          name
          type {
            name
            kind
            ofType {
              name
              kind
            }
          }
        }
      }
    }
    directives {
      name
      description
    }
  }
}
"""

# Query mínima para comprobar que el endpoint responde
TYPENAME_QUERY = "{ __typename }"

# =============================================================================
# CLIENTE GRAPHQL
# =============================================================================

class GraphQLClient:
    """
    Wrapper asíncrono sobre aiohttp para realizar peticiones GraphQL.
    Gestiona cabeceras personalizadas, timeouts y errores de red.
    """

    def __init__(
        self,
        url: str,
        headers: Dict[str, str],
        timeout: float = 30.0,
    ):
        self.url     = url
        self.headers = {
            "Content-Type": "application/json",
            "Accept":       "application/json",
            "User-Agent":   USER_AGENT,
            **headers,
        }
        self.timeout = aiohttp.ClientTimeout(total=timeout)

    async def query(
        self,
        gql: str,
        variables: Optional[Dict] = None,
        timeout_override: Optional[float] = None,
    ) -> Tuple[Optional[Dict], Optional[str]]:
        """
        Envía una query GraphQL y devuelve (data_dict, error_str).
        Nunca lanza excepción: los errores se devuelven como string.
        """
        payload: Any = {"query": gql}
        if variables:
            payload["variables"] = variables

        timeout = (
            aiohttp.ClientTimeout(total=timeout_override)
            if timeout_override is not None
            else self.timeout
        )

        try:
            async with aiohttp.ClientSession(
                headers=self.headers,
                timeout=timeout,
                connector=aiohttp.TCPConnector(ssl=False),
            ) as session:
                async with session.post(self.url, json=payload) as resp:
                    text = await resp.text()
                    try:
                        data = json.loads(text)
                    except json.JSONDecodeError:
                        return None, f"Respuesta no-JSON (HTTP {resp.status}): {text[:300]}"
                    return data, None

        except asyncio.TimeoutError:
            return None, f"TIMEOUT tras {timeout.total}s"
        except aiohttp.ClientConnectorError as exc:
            return None, f"Error de conexión: {exc}"
        except Exception as exc:
            return None, f"Error inesperado: {exc}"

    async def query_batch(
        self,
        queries: List[str],
        timeout_override: Optional[float] = None,
    ) -> Tuple[Optional[Any], Optional[str]]:
        """
        Envía un array de queries GraphQL (batch) en una sola petición HTTP.
        Devuelve (respuesta_cruda, error_str).
        """
        payload = [{"query": q} for q in queries]
        timeout = (
            aiohttp.ClientTimeout(total=timeout_override)
            if timeout_override is not None
            else self.timeout
        )
        try:
            async with aiohttp.ClientSession(
                headers=self.headers,
                timeout=timeout,
                connector=aiohttp.TCPConnector(ssl=False),
            ) as session:
                async with session.post(self.url, json=payload) as resp:
                    text = await resp.text()
                    try:
                        return json.loads(text), None
                    except json.JSONDecodeError:
                        return None, f"Batch: respuesta no-JSON (HTTP {resp.status})"
        except asyncio.TimeoutError:
            return None, f"Batch TIMEOUT tras {timeout.total}s"
        except Exception as exc:
            return None, f"Batch error: {exc}"


# =============================================================================
# CLASE PRINCIPAL DE AUDITORÍA
# =============================================================================

class GraphQLAuditor:
    """
    Orquesta las seis fases de auditoría DAST sobre un endpoint GraphQL.
    Acumula findings en self.findings y el schema en self.schema_info.
    """

    def __init__(self, client: GraphQLClient, depth: int = 7):
        self.client:      GraphQLClient = client
        self.depth:       int           = depth
        self.findings:    List[Finding] = []
        self.schema_info: SchemaInfo    = SchemaInfo()

    # -------------------------------------------------------------------------
    # Utilidades internas
    # -------------------------------------------------------------------------

    def _add(self, finding: Finding) -> None:
        """Registra un finding y lo muestra en consola."""
        self.findings.append(finding)
        color = SEV_COLOR.get(finding.severity, "white")
        console.print(
            f"  [{color}][{finding.severity}][/] {finding.title}"
        )

    def _info(self, msg: str) -> None:
        """Línea informativa de progreso."""
        console.print(f"  [dim]{msg}[/]")

    @staticmethod
    def _resolve_type_name(type_obj: Optional[Dict]) -> str:
        """
        Navega recursivamente el objeto de tipo GraphQL y devuelve el nombre
        base del tipo (sin envolturas NON_NULL / LIST).
        """
        if type_obj is None:
            return ""
        if type_obj.get("name"):
            return type_obj["name"]
        return GraphQLAuditor._resolve_type_name(type_obj.get("ofType"))

    @staticmethod
    def _looks_like_id_arg(arg_name: str, type_name: str) -> bool:
        """
        Heurística: ¿parece este argumento un identificador de recurso?
        """
        id_hints = {"id", "user_id", "userId", "account_id", "accountId",
                    "node_id", "nodeId", "uuid", "pk", "key"}
        return arg_name.lower() in id_hints or "id" in arg_name.lower()

    # -------------------------------------------------------------------------
    # Fase 0: Verificación de conectividad
    # -------------------------------------------------------------------------

    async def check_connectivity(self) -> bool:
        """
        Verifica que el endpoint responde a GraphQL antes de iniciar
        las fases de auditoría.
        """
        self._info("Verificando conectividad con el endpoint...")
        data, err = await self.client.query(TYPENAME_QUERY)
        if err:
            console.print(f"  [red]No se puede conectar: {err}[/]")
            return False
        if data and ("data" in data or "errors" in data):
            self._info("Endpoint GraphQL activo.")
            return True
        console.print("  [red]El endpoint no parece ser GraphQL.[/]")
        return False

    # -------------------------------------------------------------------------
    # Fase 1: Introspección y reconocimiento
    # -------------------------------------------------------------------------

    async def fetch_schema(self) -> Optional[Dict]:
        """
        Ejecuta la query de introspección completa y devuelve el schema
        en formato dict, o None si la introspección está deshabilitada.
        """
        data, err = await self.client.query(INTROSPECTION_QUERY)
        if err:
            self._info(f"Introspección falló con error: {err}")
            return None
        if not data:
            return None
        # Algunos servidores devuelven errors en lugar de data
        if "errors" in data and "data" not in data:
            return None
        return data.get("data", {}).get("__schema")

    async def extract_queryable_fields(self, schema: Dict) -> None:
        """
        Recorre el schema GraphQL y rellena self.schema_info con:
        - Tipos disponibles
        - Queries, Mutations, Subscriptions por nombre
        - Campos con nombres sensibles
        """
        info = self.schema_info
        types = schema.get("types", [])

        # Obtener el nombre del tipo raíz de Query y Mutation
        query_type_name  = (schema.get("queryType")  or {}).get("name", "Query")
        mut_type_name    = (schema.get("mutationType") or {}).get("name", "Mutation")
        sub_type_name    = (schema.get("subscriptionType") or {}).get("name", "Subscription")

        for t in types:
            name   = t.get("name", "")
            kind   = t.get("kind", "")
            fields = t.get("fields") or []

            # Ignorar tipos internos de GraphQL
            if name.startswith("__"):
                continue

            info.types.append(name)

            for f in fields:
                fname = f.get("name", "")

                # Clasificar como query/mutation/subscription
                if name == query_type_name:
                    info.queries.append(fname)
                elif name == mut_type_name:
                    info.mutations.append(fname)
                elif name == sub_type_name:
                    info.subscriptions.append(fname)

                # Detectar campos con nombres sensibles
                if any(s in fname.lower() for s in SENSITIVE_FIELD_NAMES):
                    entry = f"{name}.{fname}"
                    if entry not in info.sensitive_fields:
                        info.sensitive_fields.append(entry)

        info.raw_schema = schema

    async def audit_introspection(self) -> None:
        """
        FASE 1: Comprueba si la introspección está habilitada y analiza
        el schema para detectar tipos y campos sensibles.
        """
        console.rule("[bold magenta]FASE 1 — Introspección y Reconocimiento[/]")

        schema = await self.fetch_schema()

        if schema is None:
            self._add(Finding(
                tool=TOOL_NAME, severity="INFO", phase=1,
                type="Introspection Disabled",
                title="Introspección GraphQL deshabilitada",
                description=(
                    "El endpoint no responde a la query de introspección completa. "
                    "Esto es una buena práctica en producción, ya que evita exponer "
                    "el schema completo a atacantes."
                ),
                affected=self.client.url,
                recommendation=(
                    "Mantener la introspección deshabilitada en producción. "
                    "Considerar permitirla solo en entornos de desarrollo con controles de acceso."
                ),
            ))
            return

        # Introspección habilitada — finding CRITICAL
        self._add(Finding(
            tool=TOOL_NAME, severity="CRITICAL", phase=1,
            type="Introspection Enabled",
            title="Introspección GraphQL habilitada en producción",
            description=(
                "El servidor acepta queries de introspección que exponen el schema "
                "completo al atacante: todos los tipos, campos, argumentos, queries "
                "y mutations disponibles. Esto facilita enormemente la fase de "
                "reconocimiento en un ataque."
            ),
            affected=self.client.url,
            recommendation=(
                "Deshabilitar la introspección en el entorno de producción. "
                "En GraphQL-Python: GRAPHENE_SETTINGS = {'MIDDLEWARE': [...], "
                "'ATOMIC_MUTATIONS': True, 'INTROSPECTION': False}. "
                "En Apollo Server: introspection: false. "
                "Limitar la introspección a IPs o roles autorizados."
            ),
            evidence=f"Query: {INTROSPECTION_QUERY[:200].strip()}...",
        ))

        # Analizar schema
        await self.extract_queryable_fields(schema)

        # Comprobar campos con datos sensibles
        if self.schema_info.sensitive_fields:
            fields_str = ", ".join(self.schema_info.sensitive_fields[:15])
            self._add(Finding(
                tool=TOOL_NAME, severity="HIGH", phase=1,
                type="Sensitive Field Exposure",
                title="Campos con datos potencialmente sensibles en el schema",
                description=(
                    "El schema expone campos cuyos nombres sugieren que contienen "
                    "información sensible (contraseñas, tokens, claves API, datos PII). "
                    "Si estos campos son accesibles sin autenticación o autorización "
                    "adecuada, representan un riesgo crítico."
                ),
                affected=f"Campos: {fields_str}",
                recommendation=(
                    "Revisar que ningún campo sensible sea accesible sin autenticación. "
                    "Implementar resolvers con verificación de permisos. "
                    "Nunca devolver campos como 'password' o 'secret' en queries."
                ),
                evidence=f"Campos detectados: {fields_str}",
            ))

        # Comprobar si los mensajes de error revelan información interna
        # Enviamos una query intencionadamente inválida
        bad_query = "{ nonExistentField123xyz { id } }"
        data, _   = await self.client.query(bad_query)
        if data and "errors" in data:
            errors_raw = json.dumps(data["errors"])
            # Buscar indicadores de stack trace o rutas de fichero
            leak_patterns = [
                r"at\s+\w+.*?\(.*?\.js:\d+",       # Node.js stack trace
                r'File ".*?\.py", line \d+',        # Python traceback
                r"Exception in thread",              # Java
                r"Traceback \(most recent",          # Python
                r"/home/|/var/www|/usr/local",      # Rutas de fichero Unix
                r"C:\\Users\\|C:\\inetpub",          # Rutas Windows
            ]
            for pat in leak_patterns:
                if re.search(pat, errors_raw, re.IGNORECASE):
                    self._add(Finding(
                        tool=TOOL_NAME, severity="MEDIUM", phase=1,
                        type="Verbose Error Messages",
                        title="Errores GraphQL revelan información interna del servidor",
                        description=(
                            "Los mensajes de error de GraphQL incluyen trazas de pila, "
                            "rutas de fichero u otra información interna que facilita "
                            "la identificación del framework, versión y estructura "
                            "del servidor al atacante."
                        ),
                        affected=self.client.url,
                        recommendation=(
                            "Configurar el servidor para devolver mensajes de error "
                            "genéricos en producción. En Apollo: "
                            "formatError: () => ({ message: 'Internal server error' }). "
                            "En Python/Graphene: DEBUG=False."
                        ),
                        evidence=errors_raw[:500],
                    ))
                    break

        # Comprobar directivas (pueden revelar plugins/frameworks)
        directives = schema.get("directives", [])
        if directives:
            dir_names = [d.get("name", "") for d in directives]
            framework_hints = {
                "auth": "Directiva de autenticación (posiblemente graphql-auth-directives)",
                "cacheControl": "Cache-Control (Apollo Server)",
                "deprecated": "Directiva estándar",
                "rateLimit": "Directiva de rate limiting",
                "hasRole": "Control de roles en directiva",
                "isAuthenticated": "Autenticación por directiva",
            }
            for name, hint in framework_hints.items():
                if name in dir_names:
                    self._add(Finding(
                        tool=TOOL_NAME, severity="INFO", phase=1,
                        type="Framework Fingerprint",
                        title=f"Directiva '@{name}' detectada — {hint}",
                        description=(
                            f"La presencia de la directiva '@{name}' permite "
                            "identificar el framework o librería GraphQL utilizada, "
                            "lo que facilita el targeting de vulnerabilidades específicas."
                        ),
                        affected=f"Directiva: @{name}",
                        recommendation=(
                            "Considerar ocultar las directivas no esenciales. "
                            "Mantener los frameworks actualizados."
                        ),
                        evidence=f"Directivas encontradas: {', '.join(dir_names)}",
                    ))
                    break

        self._info(
            f"Schema descubierto: {len(self.schema_info.queries)} queries, "
            f"{len(self.schema_info.mutations)} mutations, "
            f"{len(self.schema_info.subscriptions)} subscriptions, "
            f"{len(self.schema_info.types)} tipos."
        )

    # -------------------------------------------------------------------------
    # Fase 2: Authorization Testing (IDOR / BOLA)
    # -------------------------------------------------------------------------

    async def audit_authorization(self) -> None:
        """
        FASE 2: Prueba IDOR/BOLA enviando IDs alternativos a cada query
        que acepte argumentos de tipo ID.
        """
        console.rule("[bold magenta]FASE 2 — Authorization Testing (IDOR/BOLA)[/]")

        schema = self.schema_info.raw_schema
        if not schema:
            self._info("Sin schema disponible — omitiendo fase 2.")
            return

        types         = schema.get("types", [])
        query_type_nm = (schema.get("queryType") or {}).get("name", "Query")
        id_test_values = ["1", "2", "3", "999", "-1", "0", "admin",
                          "null", "undefined", "true"]
        uuid_pattern = re.compile(
            r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
            re.IGNORECASE,
        )

        for t in types:
            if t.get("name") != query_type_nm:
                continue

            for f in (t.get("fields") or []):
                fname = f.get("name", "")
                args  = f.get("args") or []

                # Buscar argumentos que parezcan IDs
                id_args = [
                    a for a in args
                    if self._looks_like_id_arg(
                        a.get("name", ""),
                        self._resolve_type_name(a.get("type")),
                    )
                ]
                if not id_args:
                    continue

                self._info(f"Probando BOLA en query '{fname}' con args: "
                           f"{[a['name'] for a in id_args]}")

                responses = []
                for val in id_test_values[:5]:  # Limitamos a 5 para no ser ruidosos
                    arg_str = ", ".join(
                        f'{a["name"]}: "{val}"' for a in id_args
                    )
                    probe_query = f"{{ {fname}({arg_str}) {{ __typename }} }}"
                    data, err = await self.client.query(probe_query)
                    if err:
                        continue
                    if data and "data" in data and data["data"]:
                        # Si hay datos reales (no null), registramos la respuesta
                        inner = data["data"].get(fname)
                        if inner is not None:
                            responses.append((val, inner))

                # Heurística: si IDs diferentes devuelven respuestas con datos distintos
                # (y más de uno respondió), probable BOLA
                if len(responses) >= 2:
                    self._add(Finding(
                        tool=TOOL_NAME, severity="CRITICAL", phase=2,
                        type="BOLA / IDOR",
                        title=f"Posible BOLA/IDOR en query '{fname}'",
                        description=(
                            f"La query '{fname}' devuelve datos para múltiples IDs "
                            "distintos sin que se haya podido verificar que existe "
                            "un control de autorización a nivel de objeto. Un atacante "
                            "puede iterar IDs para acceder a recursos de otros usuarios "
                            "(Broken Object Level Authorization — CWE-639)."
                        ),
                        affected=f"{self.client.url} → query {fname}",
                        recommendation=(
                            "Implementar verificación de propiedad en cada resolver: "
                            "comparar el ID solicitado con el usuario autenticado. "
                            "Usar UUIDs en lugar de IDs secuenciales. "
                            "Aplicar middleware de autorización a nivel de campo."
                        ),
                        evidence=(
                            f"IDs probados: {[r[0] for r in responses]}. "
                            f"Respuestas recibidas: {json.dumps([r[1] for r in responses])[:300]}"
                        ),
                    ))

    # -------------------------------------------------------------------------
    # Fase 3: Rate Limiting & DoS
    # -------------------------------------------------------------------------

    async def audit_ratelimit_dos(self) -> None:
        """
        FASE 3: Prueba de alias abuse para bypass de rate limiting,
        deep nesting para DoS y batch query abuse.
        """
        console.rule("[bold magenta]FASE 3 — Rate Limiting & DoS[/]")

        schema = self.schema_info.raw_schema
        if not schema:
            self._info("Sin schema disponible — omitiendo fase 3.")
            return

        # Elegir la primera query disponible como objetivo
        target_query = (self.schema_info.queries or ["__typename"])[0]

        # ── 3a: Alias abuse ──────────────────────────────────────────────────
        self._info(f"Probando alias abuse con {ALIAS_COUNT} aliases de '{target_query}'...")
        aliases = " ".join(
            f"q{i}:{target_query} {{ __typename }}" for i in range(1, ALIAS_COUNT + 1)
        )
        alias_query = "{ " + aliases + " }"

        t0   = time.perf_counter()
        data, err = await self.client.query(alias_query, timeout_override=60.0)
        elapsed = time.perf_counter() - t0

        if not err and data:
            inner = data.get("data") or {}
            # Si la mayoría de aliases devolvieron datos → rate limiting bypass
            answered = sum(1 for k, v in inner.items() if v is not None)
            if answered >= ALIAS_COUNT // 2:
                self._add(Finding(
                    tool=TOOL_NAME, severity="HIGH", phase=3,
                    type="Rate Limit Bypass via Alias",
                    title="Rate limiting bypasseable mediante alias GraphQL",
                    description=(
                        f"El servidor respondió a {answered}/{ALIAS_COUNT} aliases "
                        "en una sola petición HTTP. Un atacante puede explotar "
                        "esta técnica para realizar miles de operaciones (p.ej. "
                        "brute-force de contraseñas o OTPs) eludiendo límites de "
                        "peticiones por IP o por token."
                    ),
                    affected=self.client.url,
                    recommendation=(
                        "Implementar query complexity analysis para rechazar queries "
                        "con demasiados campos o aliases. Usar librerías como "
                        "graphql-query-complexity (Node.js) o graphene-query-complexity "
                        "(Python). Limitar el número de aliases por query."
                    ),
                    evidence=f"Query con {ALIAS_COUNT} aliases → {answered} respuestas en {elapsed:.2f}s",
                ))

        # ── 3b: Deep nesting DoS ─────────────────────────────────────────────
        self._info(f"Probando deep nesting DoS con profundidad {self.depth}...")
        # Construir una query con nesting basado en tipos de lista disponibles
        # Si no hay tipos relacionales, usamos un campo genérico
        list_types = [
            t for t in (self.schema_info.raw_schema or {}).get("types", [])
            if t.get("kind") in ("OBJECT",) and not t["name"].startswith("__")
            and t.get("fields")
        ]

        nested_query: str
        if list_types:
            # Construir nesting real con tipos del schema
            root_type = list_types[0]
            nested_field = (root_type.get("fields") or [{}])[0].get("name", "__typename")
            inner = "{ __typename }"
            for _ in range(self.depth):
                inner = f"{{ {nested_field} {inner} }}"
            nested_query = f"{{ {self.schema_info.queries[0] if self.schema_info.queries else '__typename'} {inner} }}"
        else:
            # Fallback genérico
            inner = "{ id }"
            for _ in range(self.depth):
                inner = f"{{ node {inner} }}"
            nested_query = f"{{ user {inner} }}"

        t0      = time.perf_counter()
        data2, err2 = await self.client.query(nested_query, timeout_override=DOS_TIMEOUT_THRESHOLD + 5)
        elapsed2 = time.perf_counter() - t0

        if elapsed2 >= DOS_TIMEOUT_THRESHOLD:
            self._add(Finding(
                tool=TOOL_NAME, severity="HIGH", phase=3,
                type="Deep Nesting DoS",
                title=f"Query con anidamiento profundo ({self.depth} niveles) causa latencia excesiva",
                description=(
                    f"Una query con {self.depth} niveles de anidamiento tardó "
                    f"{elapsed2:.2f}s en responder, superando el umbral de "
                    f"{DOS_TIMEOUT_THRESHOLD}s. Esto puede traducirse en un "
                    "ataque de denegación de servicio sin autenticación previa "
                    "(CWE-400: Uncontrolled Resource Consumption)."
                ),
                affected=self.client.url,
                recommendation=(
                    "Implementar un límite de profundidad máxima de query. "
                    "En Apollo Server: depthLimit(7). "
                    "En Python/Graphene: usar graphene-complexity o middleware propio. "
                    "Establecer timeouts por resolver."
                ),
                evidence=f"Profundidad: {self.depth} | Tiempo de respuesta: {elapsed2:.2f}s",
            ))
        elif err2 and "TIMEOUT" in str(err2):
            self._add(Finding(
                tool=TOOL_NAME, severity="HIGH", phase=3,
                type="Deep Nesting DoS",
                title=f"Query con anidamiento profundo ({self.depth} niveles) causa timeout",
                description=(
                    f"Una query con {self.depth} niveles de anidamiento causó un "
                    "timeout del servidor, lo que evidencia vulnerabilidad a DoS "
                    "por complejidad de query sin protección."
                ),
                affected=self.client.url,
                recommendation=(
                    "Implementar límite de profundidad y análisis de complejidad. "
                    "Deshabilitar campos de relación circular o recursiva."
                ),
                evidence=f"Error: {err2} | Profundidad: {self.depth}",
            ))

        # ── 3c: Batch query DoS ──────────────────────────────────────────────
        self._info(f"Probando batch query con {BATCH_QUERY_COUNT} queries...")
        batch_queries = [TYPENAME_QUERY] * BATCH_QUERY_COUNT
        t0 = time.perf_counter()
        batch_data, batch_err = await self.client.query_batch(
            batch_queries, timeout_override=60.0
        )
        elapsed3 = time.perf_counter() - t0

        if batch_data and isinstance(batch_data, list):
            if len(batch_data) >= BATCH_QUERY_COUNT // 2:
                self._add(Finding(
                    tool=TOOL_NAME, severity="HIGH", phase=3,
                    type="Batch Query Abuse",
                    title="Endpoint acepta batch queries — potencial vector DoS",
                    description=(
                        f"El endpoint aceptó un array de {BATCH_QUERY_COUNT} queries "
                        "en una sola petición HTTP y respondió a "
                        f"{len(batch_data)} de ellas. "
                        "Los batch queries permiten multiplicar el trabajo del servidor "
                        "con una sola petición HTTP, evadiendo controles por petición."
                    ),
                    affected=self.client.url,
                    recommendation=(
                        "Deshabilitar el soporte de batching si no es necesario. "
                        "Si se necesita, limitar el número de operaciones por batch (ej. máx 10). "
                        "En Apollo Server: csrfPrevention: true, "
                        "allowBatchedHttpRequests: false."
                    ),
                    evidence=(
                        f"{BATCH_QUERY_COUNT} queries en batch → {len(batch_data)} "
                        f"respuestas en {elapsed3:.2f}s"
                    ),
                ))
        elif not batch_err:
            # El servidor respondió pero no con una lista (probablemente no soporta batch)
            self._info("Batch queries no soportadas — bien.")

    # -------------------------------------------------------------------------
    # Fase 4: Information Disclosure
    # -------------------------------------------------------------------------

    async def audit_info_disclosure(self) -> None:
        """
        FASE 4: Detecta divulgación de información mediante field suggestions,
        errores verbosos y exposición de directivas internas.
        """
        console.rule("[bold magenta]FASE 4 — Information Disclosure[/]")

        # ── 4a: __typename (endpoint activo + GraphQL expuesto) ──────────────
        self._info("Comprobando exposición de __typename...")
        data, err = await self.client.query(TYPENAME_QUERY)
        if not err and data and "data" in data:
            typename_val = (data.get("data") or {}).get("__typename", "")
            self._add(Finding(
                tool=TOOL_NAME, severity="INFO", phase=4,
                type="GraphQL Endpoint Exposed",
                title="Endpoint GraphQL confirmado y accesible públicamente",
                description=(
                    f"El campo '__typename' devuelve '{typename_val}', confirmando "
                    "que el endpoint GraphQL es accesible sin restricciones de red. "
                    "Este hallazgo es informativo pero puede ser el punto de partida "
                    "para todas las demás fases de ataque."
                ),
                affected=self.client.url,
                recommendation=(
                    "Verificar que el endpoint no es accesible públicamente si no "
                    "es necesario. Considerar mover la API a una ruta no predecible "
                    "o proteger el acceso con API Gateway."
                ),
                evidence=f"{{ __typename }} → {typename_val}",
            ))

        # ── 4b: Field suggestions con typo ───────────────────────────────────
        self._info("Probando field suggestions con campos con typo...")
        typo_queries = [
            "{ usr { id } }",
            "{ qurey { id } }",
            "{ prodcut { id } }",
            "{ ordr { id } }",
        ]
        suggestion_patterns = [
            r"Did you mean",
            r"¿Quisiste decir",
            r"suggestions?",
            r'"suggestion"',
        ]
        for tq in typo_queries:
            data, err = await self.client.query(tq)
            if err:
                continue
            if data and "errors" in data:
                errors_str = json.dumps(data["errors"])
                if any(re.search(p, errors_str, re.IGNORECASE)
                       for p in suggestion_patterns):
                    self._add(Finding(
                        tool=TOOL_NAME, severity="MEDIUM", phase=4,
                        type="Field Suggestion Disclosure",
                        title="El servidor sugiere nombres de campos ante typos — schema parcial expuesto",
                        description=(
                            "GraphQL devuelve sugerencias de campos cuando se envía "
                            "un nombre con error tipográfico ('Did you mean X?'). "
                            "Esto permite a un atacante reconstruir el schema aunque "
                            "la introspección esté deshabilitada, enviando queries "
                            "sistemáticas con variaciones de nombres."
                        ),
                        affected=self.client.url,
                        recommendation=(
                            "Deshabilitar las sugerencias en producción. "
                            "En Apollo Server: nodeEnv: 'production' desactiva las "
                            "sugerencias automáticamente. En Graphene: "
                            "GRAPHENE_SETTINGS = {'MIDDLEWARE': [...]}. "
                            "Usar librerías que permitan deshabilitar explícitamente "
                            "las suggestions en el formatError handler."
                        ),
                        evidence=f"Query: {tq} → {errors_str[:300]}",
                    ))
                    break  # Un ejemplo es suficiente

        # ── 4c: Directivas que revelan framework ─────────────────────────────
        self._info("Consultando directivas del schema...")
        directives_query = "{ __schema { directives { name description } } }"
        data, err = await self.client.query(directives_query)
        if not err and data:
            inner = ((data.get("data") or {}).get("__schema") or {})
            directives = inner.get("directives") or []
            non_standard = [
                d for d in directives
                if d.get("name") not in ("skip", "include", "deprecated", "specifiedBy")
            ]
            if non_standard:
                names = ", ".join(d.get("name", "") for d in non_standard)
                self._add(Finding(
                    tool=TOOL_NAME, severity="LOW", phase=4,
                    type="Custom Directive Disclosure",
                    title="Directivas personalizadas revelan detalles del framework interno",
                    description=(
                        "El endpoint expone directivas no estándar que permiten "
                        "identificar plugins, middlewares o frameworks GraphQL "
                        "específicos. Esta información ayuda al atacante a dirigir "
                        "exploits a versiones vulnerables conocidas."
                    ),
                    affected=self.client.url,
                    recommendation=(
                        "Evaluar si todas las directivas deben ser visibles. "
                        "Deshabilitar la introspección de directivas en producción."
                    ),
                    evidence=f"Directivas no estándar: {names}",
                ))

        # ── 4d: Verificar si errores de variables exponen información ─────────
        self._info("Comprobando errores con variables malformadas...")
        bad_var_query = "query Test($id: ID!) { __typename }"
        data, err = await self.client.query(bad_var_query, variables={"id": None})
        if data and "errors" in data:
            err_str = json.dumps(data["errors"])
            if len(err_str) > 200 and any(kw in err_str.lower()
                                           for kw in ["stack", "trace", "exception", "file", "line"]):
                self._add(Finding(
                    tool=TOOL_NAME, severity="MEDIUM", phase=4,
                    type="Verbose Variable Error",
                    title="Errores de validación de variables revelan detalles internos",
                    description=(
                        "Los errores producidos al enviar variables inválidas incluyen "
                        "información interna del servidor (stack traces, nombres de "
                        "fichero o número de línea), lo que facilita el reconocimiento."
                    ),
                    affected=self.client.url,
                    recommendation=(
                        "Sanitizar los mensajes de error de validación para no "
                        "incluir detalles del stack ni rutas internas."
                    ),
                    evidence=err_str[:400],
                ))

    # -------------------------------------------------------------------------
    # Fase 5: Injection Testing
    # -------------------------------------------------------------------------

    async def audit_injection(self) -> None:
        """
        FASE 5: Inyecta payloads SQLi, NoSQLi, SSTI y XSS en argumentos
        String de las queries del schema.
        """
        console.rule("[bold magenta]FASE 5 — Injection Testing[/]")

        schema = self.schema_info.raw_schema
        if not schema:
            self._info("Sin schema disponible — omitiendo fase 5.")
            return

        types         = schema.get("types", [])
        query_type_nm = (schema.get("queryType") or {}).get("name", "Query")

        # SSTI: indica evaluación si el resultado es 49 (7*7)
        ssti_eval_markers = ["49", "49.0"]

        for t in types:
            if t.get("name") != query_type_nm:
                continue

            for f in (t.get("fields") or []):
                fname = f.get("name", "")
                args  = f.get("args") or []

                # Buscar argumentos de tipo String (candidatos a inyección)
                string_args = [
                    a for a in args
                    if self._resolve_type_name(a.get("type", {})) in ("String", "")
                    and not self._looks_like_id_arg(a.get("name", ""), "")
                ]
                if not string_args:
                    continue

                arg = string_args[0]  # Probar el primer argumento String
                arg_name = arg.get("name", "input")

                # ── SQLi ────────────────────────────────────────────────────
                self._info(f"  → SQLi en {fname}({arg_name})...")
                for payload in SQLI_PAYLOADS[:2]:
                    probe = f'{{ {fname}({arg_name}: "{payload}") {{ __typename }} }}'
                    data, err = await self.client.query(probe)
                    if err:
                        continue
                    if data:
                        resp_str = json.dumps(data)
                        # Indicadores de SQLi exitoso
                        sqli_indicators = [
                            "syntax error", "sql", "mysql", "postgresql",
                            "sqlite", "ora-", "odbc", "jdbc", "unclosed",
                            "unexpected token", "you have an error in your sql",
                        ]
                        if any(ind in resp_str.lower() for ind in sqli_indicators):
                            self._add(Finding(
                                tool=TOOL_NAME, severity="CRITICAL", phase=5,
                                type="SQL Injection",
                                title=f"Posible SQL Injection en '{fname}({arg_name})'",
                                description=(
                                    "La respuesta del servidor ante un payload de "
                                    "inyección SQL contiene mensajes de error de base "
                                    "de datos, lo que indica que el input del usuario "
                                    "es interpolado directamente en una query SQL sin "
                                    "parametrización (CWE-89)."
                                ),
                                affected=f"{self.client.url} → {fname}({arg_name})",
                                recommendation=(
                                    "Usar queries parametrizadas o prepared statements. "
                                    "Nunca concatenar input del usuario en queries SQL. "
                                    "Aplicar principio de mínimo privilegio al usuario de BD."
                                ),
                                evidence=f"Payload: {payload} → {resp_str[:300]}",
                            ))
                            break

                # ── NoSQLi ──────────────────────────────────────────────────
                self._info(f"  → NoSQLi en {fname}({arg_name})...")
                for payload in NOSQLI_PAYLOADS[:2]:
                    # Los payloads NoSQL pueden enviarse como JSON en variables
                    probe     = f'query T($v: String) {{ {fname}({arg_name}: $v) {{ __typename }} }}'
                    data, err = await self.client.query(probe, variables={"v": payload})
                    if err:
                        continue
                    if data and "data" in data and data["data"]:
                        inner = data["data"].get(fname)
                        if inner is not None:
                            self._add(Finding(
                                tool=TOOL_NAME, severity="HIGH", phase=5,
                                type="NoSQL Injection",
                                title=f"Posible NoSQL Injection en '{fname}({arg_name})'",
                                description=(
                                    "El servidor devuelve datos ante un payload de "
                                    "operadores NoSQL, lo que sugiere que el input "
                                    "es deserializado o evaluado directamente en una "
                                    "query NoSQL (MongoDB, CouchDB) sin sanitización "
                                    "(CWE-943)."
                                ),
                                affected=f"{self.client.url} → {fname}({arg_name})",
                                recommendation=(
                                    "Validar y sanitizar todos los inputs antes de "
                                    "usarlos en queries de base de datos NoSQL. "
                                    "Usar schemas de validación estrictos (Joi, Zod). "
                                    "Deshabilitar operadores de consulta en inputs del usuario."
                                ),
                                evidence=f"Payload: {payload} → {json.dumps(data)[:300]}",
                            ))
                            break

                # ── SSTI ────────────────────────────────────────────────────
                self._info(f"  → SSTI en {fname}({arg_name})...")
                for payload in SSTI_PAYLOADS[:3]:
                    probe = f'{{ {fname}({arg_name}: "{payload}") {{ __typename }} }}'
                    data, err = await self.client.query(probe)
                    if err:
                        continue
                    if data:
                        resp_str = json.dumps(data)
                        if any(m in resp_str for m in ssti_eval_markers):
                            self._add(Finding(
                                tool=TOOL_NAME, severity="CRITICAL", phase=5,
                                type="SSTI — Server-Side Template Injection",
                                title=f"SSTI confirmado en '{fname}({arg_name})'",
                                description=(
                                    f"El payload '{payload}' fue evaluado por el motor "
                                    "de plantillas del servidor y devolvió '49' (7×7), "
                                    "confirmando SSTI. Esto puede permitir ejecución "
                                    "remota de código (RCE) en el servidor (CWE-94)."
                                ),
                                affected=f"{self.client.url} → {fname}({arg_name})",
                                recommendation=(
                                    "No renderizar templates con input del usuario. "
                                    "Si es necesario, usar sandboxes de evaluación. "
                                    "Aplicar escape estricto del contexto de plantilla."
                                ),
                                evidence=f"Payload: {payload} → {resp_str[:300]}",
                            ))
                            break

                # ── XSS ─────────────────────────────────────────────────────
                self._info(f"  → XSS en {fname}({arg_name})...")
                for payload in XSS_PAYLOADS[:2]:
                    safe_payload = payload.replace('"', '\\"')
                    probe = f'{{ {fname}({arg_name}: "{safe_payload}") {{ __typename }} }}'
                    data, err = await self.client.query(probe)
                    if err:
                        continue
                    if data:
                        resp_str = json.dumps(data)
                        # Si el payload aparece sin escapar en la respuesta
                        if payload in resp_str and "<script>" in resp_str:
                            self._add(Finding(
                                tool=TOOL_NAME, severity="HIGH", phase=5,
                                type="Reflected XSS via GraphQL",
                                title=f"XSS reflejado en respuesta GraphQL de '{fname}({arg_name})'",
                                description=(
                                    "El servidor devuelve el payload XSS sin escapar "
                                    "en la respuesta JSON. Si esta respuesta se renderiza "
                                    "directamente en HTML sin sanitización, puede ejecutar "
                                    "JavaScript arbitrario en el navegador del usuario "
                                    "(CWE-79)."
                                ),
                                affected=f"{self.client.url} → {fname}({arg_name})",
                                recommendation=(
                                    "Escapar todos los outputs en el cliente (React/Vue "
                                    "lo hacen por defecto). Implementar Content-Security-Policy. "
                                    "Validar y sanitizar inputs en el servidor GraphQL."
                                ),
                                evidence=f"Payload: {payload} reflejado en respuesta",
                            ))
                            break

    # -------------------------------------------------------------------------
    # Fase 6: Subscription & Mutation Security
    # -------------------------------------------------------------------------

    async def audit_subscriptions(self) -> None:
        """
        FASE 6: Comprueba seguridad de subscripciones y mutations sensibles:
        - Subscriptions sin autenticación
        - Rate limiting en mutations de auth
        - Mutations que cambian credenciales sin requerir password actual
        - Mutations que devuelven tokens sin HTTPS
        """
        console.rule("[bold magenta]FASE 6 — Subscription & Mutation Security[/]")

        schema        = self.schema_info.raw_schema
        mutations     = self.schema_info.mutations
        subscriptions = self.schema_info.subscriptions

        # ── 6a: HTTPS check ─────────────────────────────────────────────────
        parsed = urlparse(self.client.url)
        if parsed.scheme == "http":
            self._add(Finding(
                tool=TOOL_NAME, severity="HIGH", phase=6,
                type="Insecure Transport",
                title="API GraphQL accesible por HTTP sin cifrado TLS",
                description=(
                    "El endpoint GraphQL usa HTTP en lugar de HTTPS. "
                    "Los tokens de autenticación, mutations y datos sensibles "
                    "viajan en texto plano, exponiéndose a ataques Man-in-the-Middle "
                    "(CWE-319)."
                ),
                affected=self.client.url,
                recommendation=(
                    "Forzar HTTPS en producción. Configurar HSTS (Strict-Transport-Security). "
                    "Redirigir todo el tráfico HTTP a HTTPS."
                ),
                evidence=f"Scheme: {parsed.scheme}",
            ))

        # ── 6b: Subscriptions sin autenticación ──────────────────────────────
        if subscriptions:
            self._info(f"Subscriptions detectadas: {subscriptions}")
            self._add(Finding(
                tool=TOOL_NAME, severity="MEDIUM", phase=6,
                type="Subscription Auth Check Required",
                title="Subscriptions GraphQL detectadas — verificar control de acceso",
                description=(
                    f"Se han detectado {len(subscriptions)} subscription(s): "
                    f"{', '.join(subscriptions[:5])}. "
                    "Si las subscriptions no validan la autenticación en el momento "
                    "de la conexión WebSocket, cualquier cliente puede recibir eventos "
                    "en tiempo real sin autorización."
                ),
                affected=f"Subscriptions: {', '.join(subscriptions[:5])}",
                recommendation=(
                    "Verificar la autenticación en el handshake WebSocket inicial "
                    "y en cada mensaje de suscripción. "
                    "Implementar autorización a nivel de subscription resolver. "
                    "Usar el campo 'connectionParams' para pasar y validar tokens JWT."
                ),
            ))

        # ── 6c: Rate limiting en mutations de autenticación ──────────────────
        auth_muts = [m for m in mutations if m.lower() in AUTH_MUTATION_NAMES
                     or any(kw in m.lower() for kw in ["login", "signin", "auth"])]
        if auth_muts:
            self._info(f"Mutations de auth detectadas: {auth_muts}")
            # Enviar la misma mutation 5 veces rápidamente y ver si alguna es bloqueada
            test_mut = auth_muts[0]
            probe = (
                f'mutation {{ {test_mut}('
                f'email: "test@vampsecure.test", password: "test") '
                f'{{ __typename }} }}'
            )
            blocked_count = 0
            for _ in range(5):
                data, err = await self.client.query(probe)
                if not err and data and "errors" in data:
                    err_str = json.dumps(data["errors"]).lower()
                    if any(kw in err_str for kw in
                           ["rate", "too many", "limit", "throttl", "blocked"]):
                        blocked_count += 1

            if blocked_count == 0:
                self._add(Finding(
                    tool=TOOL_NAME, severity="HIGH", phase=6,
                    type="Missing Rate Limiting on Auth Mutation",
                    title=f"Mutation de autenticación '{test_mut}' sin rate limiting detectable",
                    description=(
                        f"Se enviaron 5 peticiones consecutivas a la mutation '{test_mut}' "
                        "sin recibir ninguna respuesta de throttling. Esto sugiere ausencia "
                        "de rate limiting, lo que expone a ataques de fuerza bruta "
                        "de credenciales (CWE-307)."
                    ),
                    affected=f"{self.client.url} → mutation {test_mut}",
                    recommendation=(
                        "Implementar rate limiting en mutations de autenticación "
                        "(máx 5-10 intentos por IP en 5 minutos). "
                        "Añadir CAPTCHA tras intentos fallidos. "
                        "Implementar bloqueo temporal de cuenta."
                    ),
                    evidence=f"5 peticiones enviadas → 0 respuestas de throttling",
                ))

        # ── 6d: Mutations peligrosas sin password de confirmación ─────────────
        dangerous = [m for m in mutations
                     if any(kw in m.lower() for kw in
                            ["updateemail", "changeemail", "updatepassword",
                             "changepassword", "resetpassword", "setpassword"])]
        if dangerous:
            for mut_name in dangerous[:3]:
                self._add(Finding(
                    tool=TOOL_NAME, severity="MEDIUM", phase=6,
                    type="Credential Change Without Verification",
                    title=f"Mutation '{mut_name}' — verificar si requiere password actual",
                    description=(
                        f"La mutation '{mut_name}' cambia credenciales sensibles. "
                        "Si no requiere el password actual del usuario como confirmación, "
                        "un atacante que robe la sesión puede tomar el control permanente "
                        "de la cuenta (account takeover)."
                    ),
                    affected=f"{self.client.url} → mutation {mut_name}",
                    recommendation=(
                        "Exigir el password actual al cambiar email o password. "
                        "Enviar notificación al email antiguo ante cambios de credenciales. "
                        "Implementar confirmación por email para cambios de email."
                    ),
                ))

        # ── 6e: Mutations que devuelven tokens (posible leak) ─────────────────
        if schema:
            types = schema.get("types", [])
            mut_type_nm = (schema.get("mutationType") or {}).get("name", "Mutation")
            for t in types:
                if t.get("name") != mut_type_nm:
                    continue
                for f in (t.get("fields") or []):
                    fname  = f.get("name", "")
                    ftype  = self._resolve_type_name(f.get("type", {}))
                    # Si la mutation devuelve un tipo que contiene "token" o "auth"
                    if any(kw in ftype.lower() for kw in ["token", "auth", "credential"]):
                        if parsed.scheme == "http":
                            self._add(Finding(
                                tool=TOOL_NAME, severity="CRITICAL", phase=6,
                                type="Token Exposure over HTTP",
                                title=f"Mutation '{fname}' devuelve tokens sobre HTTP sin cifrar",
                                description=(
                                    f"La mutation '{fname}' devuelve un tipo '{ftype}' "
                                    "que probablemente contiene tokens de autenticación, "
                                    "y el endpoint usa HTTP. Los tokens viajan en texto "
                                    "plano y son capturables en red (CWE-319)."
                                ),
                                affected=f"{self.client.url} → mutation {fname} → {ftype}",
                                recommendation="Migrar el endpoint a HTTPS de forma urgente.",
                            ))

    # -------------------------------------------------------------------------
    # Orquestador principal
    # -------------------------------------------------------------------------

    async def run(self) -> List[Finding]:
        """
        Ejecuta todas las fases de auditoría en orden y devuelve
        la lista consolidada de findings.
        """
        # Verificar conectividad antes de auditar
        alive = await self.check_connectivity()
        if not alive:
            return self.findings

        await self.audit_introspection()
        await self.audit_authorization()
        await self.audit_ratelimit_dos()
        await self.audit_info_disclosure()
        await self.audit_injection()
        await self.audit_subscriptions()

        return self.findings


# =============================================================================
# INFORME
# =============================================================================

class VampSecReport:
    """
    Genera informes en formato JSON y HTML dark-theme a partir
    de la lista de findings y la información del schema.
    """

    # Plantilla HTML con dark theme y colores VSL
    _HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>VampSecure Labs — GraphQL Audit Report</title>
  <style>
    :root {{
      --bg:       #0d0f14;
      --bg2:      #161b22;
      --bg3:      #1f2937;
      --border:   #30363d;
      --text:     #e6edf3;
      --muted:    #8b949e;
      --accent:   #c084fc;
      --critical: #ef4444;
      --high:     #f97316;
      --medium:   #eab308;
      --low:      #22d3ee;
      --info:     #94a3b8;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      background: var(--bg);
      color: var(--text);
      font-family: 'Segoe UI', system-ui, sans-serif;
      font-size: 14px;
      line-height: 1.6;
      padding: 0 0 60px;
    }}
    header {{
      background: linear-gradient(135deg, #1a0a2e 0%, #0d0f14 100%);
      border-bottom: 1px solid var(--border);
      padding: 32px 48px;
      display: flex;
      align-items: center;
      gap: 20px;
    }}
    header pre {{
      color: var(--accent);
      font-size: 11px;
      line-height: 1.2;
      font-family: monospace;
    }}
    header .meta {{
      margin-left: auto;
      text-align: right;
      color: var(--muted);
      font-size: 12px;
    }}
    header .meta strong {{ color: var(--text); }}
    .container {{ max-width: 1200px; margin: 0 auto; padding: 32px 48px; }}
    h2 {{
      color: var(--accent);
      font-size: 18px;
      border-bottom: 1px solid var(--border);
      padding-bottom: 8px;
      margin: 32px 0 16px;
    }}
    /* Resumen ejecutivo */
    .summary-grid {{
      display: grid;
      grid-template-columns: repeat(5, 1fr);
      gap: 12px;
      margin-bottom: 32px;
    }}
    .sev-card {{
      background: var(--bg2);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 16px;
      text-align: center;
    }}
    .sev-card .count {{ font-size: 36px; font-weight: 700; }}
    .sev-card .label {{ font-size: 11px; color: var(--muted); margin-top: 4px; }}
    .sev-critical .count {{ color: var(--critical); }}
    .sev-high     .count {{ color: var(--high);     }}
    .sev-medium   .count {{ color: var(--medium);   }}
    .sev-low      .count {{ color: var(--low);      }}
    .sev-info     .count {{ color: var(--info);     }}
    /* Tabla de findings */
    table {{ width: 100%; border-collapse: collapse; }}
    thead tr {{ background: var(--bg3); }}
    th {{
      padding: 10px 12px;
      text-align: left;
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: .05em;
      color: var(--muted);
      border-bottom: 1px solid var(--border);
    }}
    td {{
      padding: 12px;
      border-bottom: 1px solid var(--border);
      vertical-align: top;
      font-size: 13px;
    }}
    tr:hover td {{ background: var(--bg2); }}
    .badge {{
      display: inline-block;
      padding: 2px 8px;
      border-radius: 4px;
      font-size: 11px;
      font-weight: 700;
    }}
    .badge-CRITICAL {{ background:#7f1d1d; color:var(--critical); }}
    .badge-HIGH     {{ background:#7c2d12; color:var(--high);     }}
    .badge-MEDIUM   {{ background:#713f12; color:var(--medium);   }}
    .badge-LOW      {{ background:#164e63; color:var(--low);      }}
    .badge-INFO     {{ background:#1e293b; color:var(--info);     }}
    details {{ margin-top: 8px; }}
    summary {{ cursor: pointer; color: var(--muted); font-size: 12px; }}
    summary:hover {{ color: var(--text); }}
    .evidence {{
      background: var(--bg3);
      border: 1px solid var(--border);
      border-radius: 4px;
      padding: 8px 12px;
      margin-top: 6px;
      font-family: monospace;
      font-size: 11px;
      color: #a5f3fc;
      word-break: break-all;
    }}
    /* Schema */
    .schema-cols {{ display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 16px; }}
    .schema-block {{
      background: var(--bg2);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 16px;
    }}
    .schema-block h3 {{
      color: var(--accent);
      font-size: 13px;
      margin-bottom: 10px;
    }}
    .schema-block ul {{ list-style: none; }}
    .schema-block li {{
      font-size: 12px;
      font-family: monospace;
      color: var(--muted);
      padding: 2px 0;
    }}
    .schema-block li:hover {{ color: var(--text); }}
    footer {{
      text-align: center;
      color: var(--muted);
      font-size: 11px;
      margin-top: 48px;
      border-top: 1px solid var(--border);
      padding-top: 24px;
    }}
  </style>
</head>
<body>
<header>
  <pre>{banner_ascii}</pre>
  <div class="meta">
    <strong>GraphQL Security Audit</strong><br/>
    Target: {target}<br/>
    Generated: {generated}<br/>
    Tool: vamp-graphql-audit v{version}
  </div>
</header>
<div class="container">
  <h2>Resumen Ejecutivo</h2>
  <div class="summary-grid">
    <div class="sev-card sev-critical"><div class="count">{cnt_critical}</div><div class="label">CRITICAL</div></div>
    <div class="sev-card sev-high">    <div class="count">{cnt_high}</div>    <div class="label">HIGH</div></div>
    <div class="sev-card sev-medium">  <div class="count">{cnt_medium}</div>  <div class="label">MEDIUM</div></div>
    <div class="sev-card sev-low">     <div class="count">{cnt_low}</div>     <div class="label">LOW</div></div>
    <div class="sev-card sev-info">    <div class="count">{cnt_info}</div>    <div class="label">INFO</div></div>
  </div>

  <h2>Findings ({total} hallazgos)</h2>
  <table>
    <thead>
      <tr>
        <th>Fase</th>
        <th>Severidad</th>
        <th>Tipo</th>
        <th>Título / Descripción / Recomendación</th>
        <th>Afectado</th>
      </tr>
    </thead>
    <tbody>
      {rows}
    </tbody>
  </table>

  <h2>Schema Descubierto</h2>
  <div class="schema-cols">
    <div class="schema-block">
      <h3>Queries ({n_queries})</h3>
      <ul>{query_items}</ul>
    </div>
    <div class="schema-block">
      <h3>Mutations ({n_mutations})</h3>
      <ul>{mutation_items}</ul>
    </div>
    <div class="schema-block">
      <h3>Campos Sensibles ({n_sensitive})</h3>
      <ul>{sensitive_items}</ul>
    </div>
  </div>

  <footer>
    © VampSecure Studios — VampSecure Labs Security Research Division<br/>
    Generado el {generated} con vamp-graphql-audit v{version}
  </footer>
</div>
</body>
</html>"""

    def __init__(
        self,
        target:      str,
        findings:    List[Finding],
        schema_info: SchemaInfo,
    ):
        self.target      = target
        self.findings    = findings
        self.schema_info = schema_info
        self.generated   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def _counts(self) -> Dict[str, int]:
        """Cuenta findings por severidad."""
        counts: Dict[str, int] = {s: 0 for s in SEVERITIES}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def to_json(self, path: str) -> None:
        """Exporta el informe completo a JSON."""
        counts = self._counts()
        report = {
            "tool":       TOOL_NAME,
            "version":    VERSION,
            "target":     self.target,
            "generated":  self.generated,
            "summary":    counts,
            "total":      len(self.findings),
            "schema": {
                "queries":         self.schema_info.queries,
                "mutations":       self.schema_info.mutations,
                "subscriptions":   self.schema_info.subscriptions,
                "sensitive_fields": self.schema_info.sensitive_fields,
            },
            "findings": [f.to_dict() for f in self.findings],
        }
        Path(path).write_text(json.dumps(report, indent=2, ensure_ascii=False))
        console.print(f"  [green]Informe JSON guardado en:[/] {path}")

    def _html_row(self, f: Finding) -> str:
        """Genera una fila HTML para un finding."""
        evidence_block = ""
        if f.evidence:
            esc = f.evidence.replace("<", "&lt;").replace(">", "&gt;")
            evidence_block = (
                f'<details><summary>Ver evidencia</summary>'
                f'<div class="evidence">{esc}</div></details>'
            )
        desc_esc = f.description.replace("<", "&lt;").replace(">", "&gt;")
        rec_esc  = f.recommendation.replace("<", "&lt;").replace(">", "&gt;")
        aff_esc  = f.affected.replace("<", "&lt;").replace(">", "&gt;")
        return (
            f"<tr>"
            f"<td>{f.phase}</td>"
            f'<td><span class="badge badge-{f.severity}">{f.severity}</span></td>'
            f"<td>{f.type}</td>"
            f"<td><strong>{f.title}</strong><br/><small>{desc_esc}</small>"
            f"<br/><em style='color:#8b949e;font-size:12px'>↳ {rec_esc}</em>"
            f"{evidence_block}</td>"
            f"<td style='font-family:monospace;font-size:11px'>{aff_esc}</td>"
            f"</tr>"
        )

    def to_html(self, path: str) -> None:
        """Exporta el informe a HTML con dark theme VSL."""
        counts = self._counts()

        # Ordenar findings por severidad
        sev_order = {s: i for i, s in enumerate(SEVERITIES)}
        sorted_findings = sorted(
            self.findings, key=lambda f: sev_order.get(f.severity, 99)
        )

        rows = "\n".join(self._html_row(f) for f in sorted_findings)

        def _items(lst: List[str], limit: int = 50) -> str:
            if not lst:
                return "<li style='color:#555'>— ninguno —</li>"
            items = lst[:limit]
            rest  = len(lst) - limit
            html  = "".join(f"<li>{x}</li>" for x in items)
            if rest > 0:
                html += f"<li style='color:#555'>... y {rest} más</li>"
            return html

        banner_ascii = (
            "  ██╗  ██╗ ███████╗ ██╗      \n"
            "  ██║  ██║ ██╔════╝ ██║      \n"
            "  ██║  ██║ ███████╗ ██║      \n"
            "  ╚██╗██╔╝ ╚════██║ ██║      \n"
            "   ╚████╔╝  ███████║ ███████╗ \n"
            "    ╚═══╝   ╚══════╝ ╚══════╝ "
        )

        html = self._HTML_TEMPLATE.format(
            banner_ascii=banner_ascii,
            target=self.target,
            generated=self.generated,
            version=VERSION,
            cnt_critical=counts.get("CRITICAL", 0),
            cnt_high=counts.get("HIGH", 0),
            cnt_medium=counts.get("MEDIUM", 0),
            cnt_low=counts.get("LOW", 0),
            cnt_info=counts.get("INFO", 0),
            total=len(self.findings),
            rows=rows,
            n_queries=len(self.schema_info.queries),
            n_mutations=len(self.schema_info.mutations),
            n_sensitive=len(self.schema_info.sensitive_fields),
            query_items=_items(self.schema_info.queries),
            mutation_items=_items(self.schema_info.mutations),
            sensitive_items=_items(self.schema_info.sensitive_fields),
        )
        Path(path).write_text(html, encoding="utf-8")
        console.print(f"  [green]Informe HTML guardado en:[/] {path}")


# =============================================================================
# RESUMEN EN CONSOLA
# =============================================================================

def print_summary(findings: List[Finding]) -> None:
    """Imprime un resumen tabular de findings en la consola."""
    console.print()
    console.rule("[bold magenta]RESUMEN DE AUDITORÍA[/]")

    if not findings:
        console.print("[bold green]Sin findings. El endpoint parece seguro en los vectores probados.[/]")
        return

    table = Table(
        show_header=True,
        header_style="bold dim",
        box=box.SIMPLE_HEAVY,
        expand=True,
    )
    table.add_column("F", width=3, justify="center")
    table.add_column("Severidad", width=10)
    table.add_column("Tipo", width=32)
    table.add_column("Título")

    sev_order = {s: i for i, s in enumerate(SEVERITIES)}
    for f in sorted(findings, key=lambda x: sev_order.get(x.severity, 99)):
        color = SEV_COLOR.get(f.severity, "white")
        table.add_row(
            str(f.phase),
            Text(f.severity, style=color),
            f.type,
            f.title,
        )

    console.print(table)

    # Contadores por severidad
    sev_counts = {s: sum(1 for f in findings if f.severity == s) for s in SEVERITIES}
    parts = [
        f"[bold red]CRITICAL: {sev_counts['CRITICAL']}[/]",
        f"[bold orange3]HIGH: {sev_counts['HIGH']}[/]",
        f"[bold yellow]MEDIUM: {sev_counts['MEDIUM']}[/]",
        f"[bold cyan]LOW: {sev_counts['LOW']}[/]",
        f"[white]INFO: {sev_counts['INFO']}[/]",
    ]
    console.print("  " + "  |  ".join(parts))
    console.print()


# =============================================================================
# MAIN
# =============================================================================

def parse_args() -> argparse.Namespace:
    """Define y parsea los argumentos de línea de comandos."""
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description=(
            "Auditor DAST de APIs GraphQL — VampSecure Labs\n"
            "Analiza un endpoint GraphQL en 6 fases: introspección, autorización,\n"
            "rate-limiting/DoS, divulgación de información, inyecciones y mutations."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--target", "-t",
        required=True,
        metavar="URL",
        help="URL del endpoint GraphQL (ej: https://api.ejemplo.com/graphql)",
    )
    parser.add_argument(
        "--header", "-H",
        action="append",
        default=[],
        metavar="Key: Value",
        help="Cabecera HTTP adicional (repetible). Ejemplo: 'Authorization: Bearer TOKEN'",
    )
    parser.add_argument(
        "--depth", "-d",
        type=int,
        default=7,
        metavar="N",
        help="Profundidad máxima de nesting para prueba DoS (default: 7)",
    )
    parser.add_argument(
        "--json",
        metavar="FILE",
        help="Guardar informe en formato JSON",
    )
    parser.add_argument(
        "--html",
        metavar="FILE",
        help="Guardar informe en formato HTML dark-theme",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        metavar="SECS",
        help="Timeout global por petición en segundos (default: 30)",
    )
    parser.add_argument(
        "--version", "-V",
        action="version",
        version=f"%(prog)s {VERSION} — © VampSecure Studios",
    )
    return parser.parse_args()


def parse_headers(raw: List[str]) -> Dict[str, str]:
    """
    Convierte ['Key: Value', 'X-Foo: Bar'] en {'Key': 'Value', 'X-Foo': 'Bar'}.
    Ignora entradas mal formadas.
    """
    headers: Dict[str, str] = {}
    for entry in raw:
        if ": " in entry:
            k, _, v = entry.partition(": ")
            headers[k.strip()] = v.strip()
        else:
            console.print(f"  [yellow]Cabecera ignorada (formato incorrecto): {entry}[/]")
    return headers


async def main_async() -> int:
    """
    Punto de entrada asíncrono: parsea argumentos, crea cliente y auditor,
    ejecuta todas las fases y genera informes.
    Devuelve el exit code numérico.
    """
    args = parse_args()

    # Mostrar banner
    console.print(f"[bold magenta]{BANNER}[/]")
    console.print(
        Panel(
            f"[bold]Target:[/] {args.target}\n"
            f"[bold]Depth:[/]  {args.depth}\n"
            f"[bold]Timeout:[/] {args.timeout}s\n"
            f"[bold]Headers:[/] {len(args.header)} personalizadas",
            title=f"[bold]{TOOL_NAME} v{VERSION}[/]",
            border_style="magenta",
        )
    )

    # Cabeceras extra
    headers = parse_headers(args.header)

    # Inicializar cliente y auditor
    client  = GraphQLClient(args.target, headers, timeout=args.timeout)
    auditor = GraphQLAuditor(client, depth=args.depth)

    # Ejecutar auditoría
    t_start   = time.perf_counter()
    findings  = await auditor.run()
    elapsed   = time.perf_counter() - t_start

    console.print(f"\n  [dim]Auditoría completada en {elapsed:.1f}s[/]")

    # Mostrar resumen
    print_summary(findings)

    # Generar informes opcionales
    report = VampSecReport(args.target, findings, auditor.schema_info)
    if args.json:
        report.to_json(args.json)
    if args.html:
        report.to_html(args.html)

    # Calcular exit code
    has_critical_or_high = any(
        f.severity in ("CRITICAL", "HIGH") for f in findings
    )
    return 1 if has_critical_or_high else 0


def main() -> None:
    """Entrada principal: lanza el loop asyncio y gestiona el exit code."""
    try:
        exit_code = asyncio.run(main_async())
    except KeyboardInterrupt:
        console.print("\n[yellow]Auditoría interrumpida por el usuario.[/]")
        exit_code = 2
    except Exception as exc:
        console.print(f"\n[red]Error fatal: {exc}[/]")
        exit_code = 2
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
