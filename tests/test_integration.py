# © VampSecure Studios — VampSecure Labs Security Research Division
"""
test_integration.py — Tests de integración para vamp-graphql-audit
===================================================================
Utiliza mocks de aiohttp para simular servidores GraphQL sin necesitar
infraestructura real. Verifica la detección end-to-end de vulnerabilidades.
"""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from vamp_graphql_audit import (
    BATCH_QUERY_COUNT,
    GraphQLAuditor,
    GraphQLClient,
)

# ─────────────────────────────────────────────────────────────────────────────
# Mock de aiohttp reutilizable
# ─────────────────────────────────────────────────────────────────────────────

def _mock_respuesta(cuerpo: dict, status: int = 200):
    """Crea un mock de respuesta aiohttp que devuelve el cuerpo JSON dado."""
    resp_mock = MagicMock()
    resp_mock.status = status
    resp_mock.text = AsyncMock(return_value=json.dumps(cuerpo))
    resp_mock.__aenter__ = AsyncMock(return_value=resp_mock)
    resp_mock.__aexit__ = AsyncMock(return_value=False)
    return resp_mock


def _mock_session(respuesta_cuerpo: dict, status: int = 200):
    """Crea un mock de aiohttp.ClientSession que devuelve siempre la misma respuesta."""
    resp = _mock_respuesta(respuesta_cuerpo, status)
    session_mock = MagicMock()
    session_mock.post = MagicMock(return_value=resp)
    session_mock.__aenter__ = AsyncMock(return_value=session_mock)
    session_mock.__aexit__ = AsyncMock(return_value=False)
    return session_mock


# ─────────────────────────────────────────────────────────────────────────────
# Test 1: Introspección habilitada detectada como CRITICAL
# ─────────────────────────────────────────────────────────────────────────────

class TestIntegrationIntrospection:
    """Verifica que una respuesta con schema GraphQL genera finding CRITICAL."""

    @pytest.mark.asyncio
    async def test_introspection_enabled_genera_finding_critical(self):
        """
        Mock del servidor devuelve un schema Apollo típico.
        La tool debe detectar la introspección como CRITICAL.
        """
        schema_response = {
            "data": {
                "__schema": {
                    "queryType": {"name": "Query"},
                    "mutationType": None,
                    "subscriptionType": None,
                    "types": [
                        {
                            "name": "Query",
                            "kind": "OBJECT",
                            "description": None,
                            "fields": [
                                {"name": "user", "isDeprecated": False,
                                 "deprecationReason": None,
                                 "type": {"name": "User", "kind": "OBJECT", "ofType": None},
                                 "args": [{"name": "id", "type": {"name": "ID", "kind": "SCALAR", "ofType": None}}]}
                            ],
                        }
                    ],
                    "directives": [],
                }
            }
        }

        cliente = GraphQLClient("http://apollo.test/graphql", {})
        auditor = GraphQLAuditor(cliente)

        # Mockeamos el método query para simular respuesta del servidor
        async def mock_query(gql_str, variables=None, timeout_override=None):
            if "__schema" in gql_str:
                return schema_response, None
            return {"data": {"__typename": "Query"}}, None

        with patch.object(cliente, "query", side_effect=mock_query):
            await auditor.audit_introspection()

        severidades_criticas = [f for f in auditor.findings if f.severity == "CRITICAL"]
        assert len(severidades_criticas) >= 1
        assert any("Introspección" in f.title for f in severidades_criticas)

    @pytest.mark.asyncio
    async def test_introspection_disabled_genera_finding_info(self):
        """Si el servidor no responde con schema, se genera finding INFO."""
        cliente = GraphQLClient("http://apollo.test/graphql", {})
        auditor = GraphQLAuditor(cliente)

        async def mock_query(gql_str, variables=None, timeout_override=None):
            # Sin datos → introspección deshabilitada
            return {"errors": [{"message": "Field '__schema' not found"}]}, None

        with patch.object(cliente, "query", side_effect=mock_query):
            await auditor.audit_introspection()

        info_findings = [f for f in auditor.findings if f.severity == "INFO"]
        assert any("Introspección" in f.title or "deshabilitada" in f.title
                   for f in info_findings)


# ─────────────────────────────────────────────────────────────────────────────
# Test 2: Schema con campos sensibles genera finding HIGH
# ─────────────────────────────────────────────────────────────────────────────

class TestIntegrationCamposSensibles:
    """Verifica que campos sensibles en el schema generan finding HIGH."""

    @pytest.mark.asyncio
    async def test_schema_con_password_genera_finding_high(self):
        """Un schema con campo 'password' en un tipo debe generar HIGH."""
        schema_response = {
            "data": {
                "__schema": {
                    "queryType": {"name": "Query"},
                    "mutationType": None,
                    "subscriptionType": None,
                    "types": [
                        {
                            "name": "Query",
                            "kind": "OBJECT",
                            "description": None,
                            "fields": [
                                {"name": "currentUser", "isDeprecated": False,
                                 "deprecationReason": None,
                                 "type": {"name": "User", "kind": "OBJECT", "ofType": None},
                                 "args": []}
                            ],
                        },
                        {
                            "name": "User",
                            "kind": "OBJECT",
                            "description": None,
                            "fields": [
                                {"name": "id", "isDeprecated": False, "deprecationReason": None,
                                 "type": {"name": "ID", "kind": "SCALAR", "ofType": None}, "args": []},
                                # Campo sensible: password
                                {"name": "password", "isDeprecated": False, "deprecationReason": None,
                                 "type": {"name": "String", "kind": "SCALAR", "ofType": None}, "args": []},
                                # Campo sensible: api_key
                                {"name": "api_key", "isDeprecated": False, "deprecationReason": None,
                                 "type": {"name": "String", "kind": "SCALAR", "ofType": None}, "args": []},
                            ],
                        },
                    ],
                    "directives": [],
                }
            }
        }

        cliente = GraphQLClient("http://apollo.test/graphql", {})
        auditor = GraphQLAuditor(cliente)

        async def mock_query(gql_str, variables=None, timeout_override=None):
            if "__schema" in gql_str:
                return schema_response, None
            return {"data": {"__typename": "Query"}}, None

        with patch.object(cliente, "query", side_effect=mock_query):
            await auditor.audit_introspection()

        high_findings = [f for f in auditor.findings if f.severity == "HIGH"]
        assert any("sensible" in f.title.lower() or "Sensitive" in f.type
                   for f in high_findings)


# ─────────────────────────────────────────────────────────────────────────────
# Test 3: APQ PersistedQueryNotFound → finding HIGH
# ─────────────────────────────────────────────────────────────────────────────

class TestIntegrationAPQ:
    """Verifica la detección de Automatic Persisted Queries (APQ)."""

    @pytest.mark.asyncio
    async def test_apq_persistedquerynotfound_genera_high(self):
        """PersistedQueryNotFound en respuesta APQ debe generar finding HIGH."""
        respuesta_apq = {
            "errors": [{"message": "PersistedQueryNotFound"}]
        }

        cliente = GraphQLClient("http://apollo.test/graphql", {})
        auditor = GraphQLAuditor(cliente)
        findings_apq: list = []

        # Simulamos la respuesta HTTP con una sesión mock
        session_mock = _mock_session(respuesta_apq)

        with patch("aiohttp.ClientSession", return_value=session_mock):
            await auditor._test_apq(
                url=cliente.url,
                headers=cliente.headers,
                findings=findings_apq,
            )

        # Debe generar finding HIGH por APQ habilitadas
        altos = [f for f in findings_apq if f.severity == "HIGH"]
        assert len(altos) >= 1
        assert any("APQ" in f.type or "PersistedQuery" in f.title for f in altos)

    @pytest.mark.asyncio
    async def test_apq_sin_soporte_genera_info(self):
        """Respuesta sin error de APQ debe generar finding INFO."""
        respuesta_sin_apq = {
            "errors": [{"message": "Cannot query field 'nonExistentField'"}]
        }

        cliente = GraphQLClient("http://apollo.test/graphql", {})
        auditor = GraphQLAuditor(cliente)
        findings_apq: list = []

        session_mock = _mock_session(respuesta_sin_apq)

        with patch("aiohttp.ClientSession", return_value=session_mock):
            await auditor._test_apq(
                url=cliente.url,
                headers=cliente.headers,
                findings=findings_apq,
            )

        info_findings = [f for f in findings_apq if f.severity == "INFO"]
        assert len(info_findings) >= 1


# ─────────────────────────────────────────────────────────────────────────────
# Test 4: Batching abuse → finding MEDIUM
# ─────────────────────────────────────────────────────────────────────────────

class TestIntegrationBatchingAbuse:
    """Verifica la detección de batch queries abusivas."""

    @pytest.mark.asyncio
    async def test_batch_50_queries_genera_medium(self):
        """Un servidor que acepta 50 queries en batch debe generar finding MEDIUM."""
        # Respuesta: lista con 50 respuestas exitosas
        respuesta_batch = [
            {"data": {"__typename": "Query"}}
            for _ in range(BATCH_QUERY_COUNT)
        ]

        cliente = GraphQLClient("http://apollo.test/graphql", {})
        auditor = GraphQLAuditor(cliente)

        async def mock_query_batch(queries, timeout_override=None):
            return respuesta_batch, None

        with patch.object(cliente, "query_batch", side_effect=mock_query_batch):
            await auditor.audit_batching_abuse()

        medium_findings = [f for f in auditor.findings if f.severity in ("MEDIUM", "HIGH")]
        assert len(medium_findings) >= 1
        assert any("Batching" in f.type or "batch" in f.title.lower()
                   for f in medium_findings)


# ─────────────────────────────────────────────────────────────────────────────
# Test 5: Field suggestion en errores → finding MEDIUM
# ─────────────────────────────────────────────────────────────────────────────

class TestIntegrationFieldSuggestion:
    """Verifica la detección de field suggestions que exponen el schema."""

    @pytest.mark.asyncio
    async def test_field_suggestion_en_errores_genera_medium(self):
        """
        Si el servidor devuelve 'Did you mean X?' ante un typo,
        debe detectarse como MEDIUM (Information Disclosure).
        """
        respuesta_con_sugerencia = {
            "errors": [
                {
                    "message": (
                        "Cannot query field 'usr' on type 'Query'. "
                        'Did you mean "user"?'
                    )
                }
            ]
        }

        cliente = GraphQLClient("http://apollo.test/graphql", {})
        auditor = GraphQLAuditor(cliente)

        async def mock_query(gql_str, variables=None, timeout_override=None):
            return respuesta_con_sugerencia, None

        with patch.object(cliente, "query", side_effect=mock_query):
            await auditor.audit_info_disclosure()

        medium_findings = [f for f in auditor.findings if f.severity == "MEDIUM"]
        assert any("suggestion" in f.type.lower() or "suger" in f.title.lower()
                   for f in medium_findings)
