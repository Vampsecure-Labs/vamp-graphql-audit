# © VampSecure Studios — VampSecure Labs Security Research Division
"""
test_unit.py — Tests unitarios para vamp-graphql-audit
=======================================================
Cubre: Finding, SchemaInfo, GraphQLAuditor (métodos síncronos y estáticos),
constantes de configuración y lógica de detección pura sin red.
"""

import pytest
import asyncio

import vamp_graphql_audit as gql
from vamp_graphql_audit import (
    Finding, SchemaInfo, GraphQLClient, GraphQLAuditor,
    BATCH_QUERY_COUNT, DOS_TIMEOUT_THRESHOLD, SENSITIVE_FIELD_NAMES,
    SEVERITIES,
)


# ─────────────────────────────────────────────────────────────────────────────
# Tests del dataclass Finding
# ─────────────────────────────────────────────────────────────────────────────

class TestFinding:
    """Tests unitarios del dataclass Finding y su serialización."""

    def test_to_dict_contiene_todas_las_claves(self, finding_ejemplo):
        """to_dict debe incluir todas las claves del esquema de hallazgo."""
        claves_esperadas = {
            "tool", "severity", "type", "title", "description",
            "affected", "recommendation", "evidence", "phase",
        }
        resultado = finding_ejemplo.to_dict()
        assert set(resultado.keys()) == claves_esperadas

    def test_to_dict_valores_correctos(self, finding_ejemplo):
        """to_dict debe preservar los valores del Finding original."""
        d = finding_ejemplo.to_dict()
        assert d["severity"] == "HIGH"
        assert d["tool"] == "vamp-graphql-audit"
        assert d["phase"] == 1
        assert d["evidence"] == "Evidencia de prueba"

    def test_to_dict_phase_es_entero(self, finding_ejemplo):
        """El campo phase debe serializarse como entero."""
        d = finding_ejemplo.to_dict()
        assert isinstance(d["phase"], int)

    def test_finding_evidence_opcional_none(self):
        """Evidence es opcional y por defecto None."""
        f = Finding(
            tool="t", severity="INFO", type="T",
            title="T", description="D", affected="A", recommendation="R",
        )
        assert f.evidence is None
        assert f.to_dict()["evidence"] is None


# ─────────────────────────────────────────────────────────────────────────────
# Tests del dataclass SchemaInfo
# ─────────────────────────────────────────────────────────────────────────────

class TestSchemaInfo:
    """Tests del dataclass SchemaInfo y sus valores por defecto."""

    def test_defaults_listas_vacias(self):
        """Todos los campos de lista deben inicializarse vacíos."""
        schema = SchemaInfo()
        assert schema.types == []
        assert schema.queries == []
        assert schema.mutations == []
        assert schema.subscriptions == []
        assert schema.sensitive_fields == []

    def test_default_raw_schema_none(self):
        """raw_schema debe ser None por defecto."""
        schema = SchemaInfo()
        assert schema.raw_schema is None


# ─────────────────────────────────────────────────────────────────────────────
# Tests de métodos estáticos de GraphQLAuditor
# ─────────────────────────────────────────────────────────────────────────────

class TestResolveTypeName:
    """Tests del método estático _resolve_type_name."""

    def test_nombre_directo(self):
        """Tipo con nombre directo lo devuelve tal cual."""
        tipo = {"name": "String", "kind": "SCALAR", "ofType": None}
        assert GraphQLAuditor._resolve_type_name(tipo) == "String"

    def test_anidado_en_oftype(self):
        """Tipo envuelto en NON_NULL debe navegar ofType para encontrar el nombre base."""
        tipo = {
            "name": None,
            "kind": "NON_NULL",
            "ofType": {"name": "Int", "kind": "SCALAR", "ofType": None},
        }
        assert GraphQLAuditor._resolve_type_name(tipo) == "Int"

    def test_doble_anidado(self):
        """Tipo envuelto en LIST y NON_NULL debe llegar al nombre base correcto."""
        tipo = {
            "name": None,
            "kind": "NON_NULL",
            "ofType": {
                "name": None,
                "kind": "LIST",
                "ofType": {"name": "User", "kind": "OBJECT", "ofType": None},
            },
        }
        assert GraphQLAuditor._resolve_type_name(tipo) == "User"

    def test_none_devuelve_cadena_vacia(self):
        """None como argumento devuelve cadena vacía."""
        assert GraphQLAuditor._resolve_type_name(None) == ""


class TestLooksLikeIdArg:
    """Tests del método estático _looks_like_id_arg."""

    def test_arg_id_simple(self):
        """Argumento llamado 'id' debe ser identificado como ID."""
        assert GraphQLAuditor._looks_like_id_arg("id", "ID") is True

    def test_arg_userid(self):
        """Argumento 'userId' debe ser identificado como ID."""
        assert GraphQLAuditor._looks_like_id_arg("userId", "String") is True

    def test_arg_uuid(self):
        """Argumento 'uuid' debe ser identificado como ID."""
        assert GraphQLAuditor._looks_like_id_arg("uuid", "String") is True

    def test_arg_no_id(self):
        """Argumento 'name' no es un ID."""
        assert GraphQLAuditor._looks_like_id_arg("name", "String") is False

    def test_arg_email_no_id(self):
        """Argumento 'email' no es un ID."""
        assert GraphQLAuditor._looks_like_id_arg("email", "String") is False


# ─────────────────────────────────────────────────────────────────────────────
# Tests de extract_queryable_fields (async)
# ─────────────────────────────────────────────────────────────────────────────

class TestExtractQueryableFields:
    """Tests del método async extract_queryable_fields."""

    @pytest.mark.asyncio
    async def test_queries_extraidas_correctamente(self, auditor, schema_apollo_tipico):
        """Las queries del schema deben aparecer en schema_info.queries."""
        await auditor.extract_queryable_fields(schema_apollo_tipico)
        assert "users" in auditor.schema_info.queries
        assert "products" in auditor.schema_info.queries

    @pytest.mark.asyncio
    async def test_mutations_extraidas_correctamente(self, auditor, schema_apollo_tipico):
        """Las mutations del schema deben aparecer en schema_info.mutations."""
        await auditor.extract_queryable_fields(schema_apollo_tipico)
        assert "login" in auditor.schema_info.mutations

    @pytest.mark.asyncio
    async def test_campos_sensibles_detectados(self, auditor, schema_apollo_tipico):
        """Campos con nombres sensibles (password, email) deben detectarse."""
        await auditor.extract_queryable_fields(schema_apollo_tipico)
        # El tipo User tiene campos 'email' y 'password'
        campos_sensibles = auditor.schema_info.sensitive_fields
        assert any("password" in c for c in campos_sensibles)

    @pytest.mark.asyncio
    async def test_tipos_internos_ignorados(self, auditor, schema_apollo_tipico):
        """Los tipos que empiezan por '__' (introspección) no se incluyen en types."""
        schema_con_interno = dict(schema_apollo_tipico)
        schema_con_interno["types"] = schema_apollo_tipico["types"] + [
            {"name": "__Schema", "kind": "OBJECT", "fields": [], "description": None}
        ]
        await auditor.extract_queryable_fields(schema_con_interno)
        assert "__Schema" not in auditor.schema_info.types

    @pytest.mark.asyncio
    async def test_raw_schema_almacenado(self, auditor, schema_apollo_tipico):
        """El schema crudo debe almacenarse en schema_info.raw_schema."""
        await auditor.extract_queryable_fields(schema_apollo_tipico)
        assert auditor.schema_info.raw_schema == schema_apollo_tipico


# ─────────────────────────────────────────────────────────────────────────────
# Tests de constantes y configuración
# ─────────────────────────────────────────────────────────────────────────────

class TestConstantes:
    """Tests de constantes críticas de configuración."""

    def test_batch_query_count_es_50(self):
        """BATCH_QUERY_COUNT debe ser exactamente 50."""
        assert BATCH_QUERY_COUNT == 50

    def test_dos_timeout_threshold_es_5(self):
        """DOS_TIMEOUT_THRESHOLD debe ser 5.0 segundos."""
        assert DOS_TIMEOUT_THRESHOLD == 5.0

    def test_severities_orden_correcto(self):
        """Las severidades deben estar en orden descendente de criticidad."""
        assert SEVERITIES[0] == "CRITICAL"
        assert SEVERITIES[-1] == "INFO"

    def test_sensitive_field_names_contiene_password(self):
        """SENSITIVE_FIELD_NAMES debe incluir 'password'."""
        assert "password" in SENSITIVE_FIELD_NAMES

    def test_sensitive_field_names_contiene_token(self):
        """SENSITIVE_FIELD_NAMES debe incluir 'token'."""
        assert "token" in SENSITIVE_FIELD_NAMES

    def test_sensitive_field_names_contiene_api_key(self):
        """SENSITIVE_FIELD_NAMES debe incluir 'api_key'."""
        assert "api_key" in SENSITIVE_FIELD_NAMES


# ─────────────────────────────────────────────────────────────────────────────
# Tests del cliente GraphQL
# ─────────────────────────────────────────────────────────────────────────────

class TestGraphQLClientInit:
    """Tests de inicialización del GraphQLClient."""

    def test_headers_incluyen_content_type(self, cliente_graphql):
        """Las cabeceras del cliente deben incluir Content-Type: application/json."""
        assert cliente_graphql.headers["Content-Type"] == "application/json"

    def test_headers_incluyen_accept(self, cliente_graphql):
        """Las cabeceras deben incluir Accept: application/json."""
        assert cliente_graphql.headers["Accept"] == "application/json"

    def test_url_almacenada(self, cliente_graphql):
        """La URL del cliente debe almacenarse correctamente."""
        assert cliente_graphql.url == "http://test.local/graphql"

    def test_headers_custom_combinados(self):
        """Los headers personalizados deben combinarse con los por defecto."""
        cliente = GraphQLClient(
            "http://test/graphql",
            {"Authorization": "Bearer TOKEN"},
        )
        assert "Authorization" in cliente.headers
        assert cliente.headers["Authorization"] == "Bearer TOKEN"
        assert "Content-Type" in cliente.headers
