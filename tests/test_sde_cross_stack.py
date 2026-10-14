"""Tests for Phase P7: Cross-Stack Interface and Schema Consensus Verifier (Invariant I8).

Verifies:
- Frontend API invocation extraction (fetch, axios, typed hooks).
- Backend router extraction (FastAPI, Flask, Express, Pydantic schemas).
- Path template normalization and matching.
- Detection of endpoint hallucination (frontend calls non-existent route).
- Detection of HTTP verb mismatch (POST vs GET).
- Detection of missing required payload fields.
- End-to-end CrossStackVerifier approval of consistent full-stack mutations and rejection of drift.
"""

import pytest

from agentpoi_sde.schema.contract_model import (
    BackendRoute,
    EndpointContract,
    FrontendCall,
    HTTPMethod,
    SchemaField,
)
from agentpoi_sde.schema.frontend_extractor import FrontendCallExtractor
from agentpoi_sde.schema.backend_extractor import BackendRouteExtractor
from agentpoi_sde.schema.cross_stack_verifier import CrossStackVerifier, CrossStackResult


class TestCrossStackContractModels:
    """Tests for universal endpoint contracts."""

    def test_path_normalization(self):
        """Path templates with Express (:id) or FastAPI ({id}) normalize identically."""
        c1 = EndpointContract(method=HTTPMethod.GET, path_template="/api/users/{user_id}")
        c2 = EndpointContract(method=HTTPMethod.GET, path_template="/api/users/:user_id")

        assert c1.normalized_path == c2.normalized_path
        assert c1.normalized_path == "/api/users/{}"


class TestFrontendExtractor:
    """Tests for extracting API client calls from frontend code."""

    def test_extract_fetch_call(self):
        js_code = """
        async function loadProfile(id) {
            const res = await fetch(`/api/users/${id}`, {
                method: 'GET'
            });
            return res.json();
        }
        """
        extractor = FrontendCallExtractor()
        calls = extractor.extract_calls("frontend/src/api.js", js_code)

        assert len(calls) == 1
        assert calls[0].method == HTTPMethod.GET
        assert "/api/users/" in calls[0].raw_path

    def test_extract_axios_post_with_body(self):
        ts_code = """
        export const submitDisbursement = async (payeeId: string, amount: number) => {
            return await axios.post('/api/v1/disburse', {
                payee_id: payeeId,
                amount: amount,
                currency: 'USD'
            });
        };
        """
        extractor = FrontendCallExtractor()
        calls = extractor.extract_calls("frontend/src/disburse.ts", ts_code)

        assert len(calls) == 1
        call = calls[0]
        assert call.method == HTTPMethod.POST
        assert call.raw_path == "/api/v1/disburse"
        assert set(call.payload_keys) == {"payee_id", "amount", "currency"}


class TestBackendExtractor:
    """Tests for extracting route definitions from backend Python code."""

    def test_extract_fastapi_routes(self):
        py_code = """
from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter()

class DisburseRequest(BaseModel):
    payee_id: str
    amount: float
    currency: str

@router.post("/api/v1/disburse")
def process_wire(req: DisburseRequest):
    return {"status": "ok"}

@router.get("/api/v1/users/{user_id}")
def get_user(user_id: str):
    return {"id": user_id}
        """
        extractor = BackendRouteExtractor()
        routes = extractor.extract_routes("backend/routers/api.py", py_code)

        assert len(routes) == 2
        route_map = {r.path_template: r for r in routes}

        assert "/api/v1/disburse" in route_map
        disburse_route = route_map["/api/v1/disburse"]
        assert disburse_route.method == HTTPMethod.POST
        assert "payee_id" in disburse_route.required_fields
        assert "amount" in disburse_route.required_fields
        assert "currency" in disburse_route.required_fields

        assert "/api/v1/users/{user_id}" in route_map
        user_route = route_map["/api/v1/users/{user_id}"]
        assert user_route.method == HTTPMethod.GET


class TestCrossStackVerifier:
    """Tests for validating full-stack cross-stack consistency."""

    def test_consistent_frontend_and_backend(self):
        """Matching paths, methods, and payload fields result in PASSED."""
        frontend_code = """
        axios.post('/api/v1/disburse', {
            payee_id: 'PAYEE-01',
            amount: 5000.0,
            currency: 'USD'
        });
        """
        backend_code = """
@router.post("/api/v1/disburse")
def disburse(req: DisburseRequest):  # requires payee_id, amount, currency
    pass
        """
        f_extractor = FrontendCallExtractor()
        b_extractor = BackendRouteExtractor()

        calls = f_extractor.extract_calls("app.ts", frontend_code)
        # Mock backend routes with expected fields
        routes = [
            BackendRoute(
                method=HTTPMethod.POST,
                path_template="/api/v1/disburse",
                required_fields=["payee_id", "amount", "currency"],
                file_path="router.py",
                line=1,
            )
        ]

        verifier = CrossStackVerifier()
        result = verifier.verify(calls, routes)

        assert result.is_consistent is True
        assert len(result.violations) == 0

    def test_detect_hallucinated_endpoint(self):
        """Frontend calling an endpoint that backend does not declare produces violation."""
        calls = [
            FrontendCall(
                method=HTTPMethod.GET,
                raw_path="/api/v1/non_existent_endpoint",
                file_path="client.ts",
                line=10,
            )
        ]
        routes = [
            BackendRoute(
                method=HTTPMethod.GET,
                path_template="/api/v1/users",
                required_fields=[],
                file_path="router.py",
                line=5,
            )
        ]

        verifier = CrossStackVerifier()
        result = verifier.verify(calls, routes)

        assert result.is_consistent is False
        assert any("ENDPOINT_NOT_FOUND" in v.code for v in result.violations)

    def test_detect_http_method_mismatch(self):
        """Frontend calling POST when backend expects GET produces violation."""
        calls = [
            FrontendCall(
                method=HTTPMethod.POST,
                raw_path="/api/v1/reports",
                file_path="client.ts",
                line=15,
            )
        ]
        routes = [
            BackendRoute(
                method=HTTPMethod.GET,
                path_template="/api/v1/reports",
                required_fields=[],
                file_path="router.py",
                line=20,
            )
        ]

        verifier = CrossStackVerifier()
        result = verifier.verify(calls, routes)

        assert result.is_consistent is False
        assert any("METHOD_MISMATCH" in v.code for v in result.violations)

    def test_detect_missing_required_payload_field(self):
        """Frontend omitting a required payload parameter produces schema drift violation."""
        calls = [
            FrontendCall(
                method=HTTPMethod.POST,
                raw_path="/api/v1/disburse",
                payload_keys=["payee_id", "amount"],  # Missing 'currency'
                file_path="client.ts",
                line=22,
            )
        ]
        routes = [
            BackendRoute(
                method=HTTPMethod.POST,
                path_template="/api/v1/disburse",
                required_fields=["payee_id", "amount", "currency"],
                file_path="router.py",
                line=10,
            )
        ]

        verifier = CrossStackVerifier()
        result = verifier.verify(calls, routes)

        assert result.is_consistent is False
        assert any("MISSING_REQUIRED_FIELD" in v.code for v in result.violations)
        assert any("currency" in v.message for v in result.violations)
