# © VampSecure Studios — VampSecure Labs Security Research Division
"""
conftest.py — Fixtures compartidos para los tests de vamp-graphql-audit
"""

import os
import sys

# Añadir el directorio padre al path para importar el módulo bajo prueba
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


import pytest

import vamp_graphql_audit as gql

# ─────────────────────────────────────────────────────────────────────────────
# Fixtures de datos de schema GraphQL
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def schema_apollo_tipico():
    """Schema GraphQL típico de un servidor Apollo con instrospección habilitada."""
    return {
        "queryType": {"name": "Query"},
        "mutationType": {"name": "Mutation"},
        "subscriptionType": None,
        "types": [
            {
                "name": "Query",
                "kind": "OBJECT",
                "description": None,
                "fields": [
                    {
                        "name": "users",
                        "isDeprecated": False,
                        "deprecationReason": None,
                        "type": {"name": "User", "kind": "OBJECT", "ofType": None},
                        "args": [
                            {
                                "name": "id",
                                "type": {"name": "ID", "kind": "SCALAR", "ofType": None},
                            }
                        ],
                    },
                    {
                        "name": "products",
                        "isDeprecated": False,
                        "deprecationReason": None,
                        "type": {"name": "Product", "kind": "OBJECT", "ofType": None},
                        "args": [
                            {
                                "name": "name",
                                "type": {"name": "String", "kind": "SCALAR", "ofType": None},
                            }
                        ],
                    },
                ],
            },
            {
                "name": "Mutation",
                "kind": "OBJECT",
                "description": None,
                "fields": [
                    {
                        "name": "login",
                        "isDeprecated": False,
                        "deprecationReason": None,
                        "type": {"name": "AuthPayload", "kind": "OBJECT", "ofType": None},
                        "args": [
                            {
                                "name": "email",
                                "type": {"name": "String", "kind": "SCALAR", "ofType": None},
                            },
                            {
                                "name": "password",
                                "type": {"name": "String", "kind": "SCALAR", "ofType": None},
                            },
                        ],
                    }
                ],
            },
            {
                "name": "User",
                "kind": "OBJECT",
                "description": None,
                "fields": [
                    {"name": "id", "isDeprecated": False, "deprecationReason": None,
                     "type": {"name": "ID", "kind": "SCALAR", "ofType": None}, "args": []},
                    {"name": "email", "isDeprecated": False, "deprecationReason": None,
                     "type": {"name": "String", "kind": "SCALAR", "ofType": None}, "args": []},
                    {"name": "password", "isDeprecated": False, "deprecationReason": None,
                     "type": {"name": "String", "kind": "SCALAR", "ofType": None}, "args": []},
                ],
            },
        ],
        "directives": [
            {"name": "skip", "description": "Directiva estándar"},
            {"name": "include", "description": "Directiva estándar"},
            {"name": "cacheControl", "description": "Apollo cache"},
        ],
    }


@pytest.fixture
def cliente_graphql():
    """Instancia de GraphQLClient configurada para tests (sin red)."""
    return gql.GraphQLClient("http://test.local/graphql", {}, timeout=5.0)


@pytest.fixture
def auditor(cliente_graphql):
    """Instancia de GraphQLAuditor configurada para tests."""
    return gql.GraphQLAuditor(cliente_graphql, depth=7)


@pytest.fixture
def finding_ejemplo():
    """Finding de ejemplo para tests de serialización."""
    return gql.Finding(
        tool="vamp-graphql-audit",
        severity="HIGH",
        type="Test Finding",
        title="Título de prueba",
        description="Descripción de prueba",
        affected="http://test.local/graphql",
        recommendation="Recomendación de prueba",
        evidence="Evidencia de prueba",
        phase=1,
    )
