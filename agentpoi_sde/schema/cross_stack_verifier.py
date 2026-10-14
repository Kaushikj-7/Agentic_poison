"""Deterministic verification sink for Cross-Stack API and Schema Consensus (Invariant I8)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from agentpoi_sde.schema.contract_model import BackendRoute, FrontendCall


@dataclass(frozen=True)
class CrossStackViolation:
    """A detected inconsistency between frontend call and backend route."""

    code: str  # ENDPOINT_NOT_FOUND, METHOD_MISMATCH, MISSING_REQUIRED_FIELD
    message: str
    frontend_call: FrontendCall
    matching_route: Optional[BackendRoute] = None


@dataclass(frozen=True)
class CrossStackResult:
    """Outcome of cross-stack interface verification."""

    is_consistent: bool
    violations: List[CrossStackViolation] = field(default_factory=list)


class CrossStackVerifier:
    """Validates that frontend API invocations strictly conform to backend route contracts."""

    def verify(self, calls: List[FrontendCall], routes: List[BackendRoute]) -> CrossStackResult:
        """Evaluates frontend calls against declared backend routes."""
        violations: List[CrossStackViolation] = []

        # Index routes by normalized path
        routes_by_path: dict[str, List[BackendRoute]] = {}
        for r in routes:
            routes_by_path.setdefault(r.normalized_path, []).append(r)

        for call in calls:
            self._verify_single_call(call, routes_by_path, violations)

        return CrossStackResult(
            is_consistent=len(violations) == 0,
            violations=violations,
        )

    def _verify_single_call(
        self,
        call: FrontendCall,
        routes_by_path: dict[str, List[BackendRoute]],
        violations: List[CrossStackViolation],
    ) -> None:
        """Verifies an individual frontend call against available backend routes."""
        matching_path_routes = routes_by_path.get(call.normalized_path)

        if not matching_path_routes:
            # Endpoint does not exist in backend
            violations.append(
                CrossStackViolation(
                    code="I8:ENDPOINT_NOT_FOUND",
                    message=(
                        f"Frontend call '{call.method.value} {call.raw_path}' in "
                        f"{call.file_path}:{call.line} targets non-existent backend endpoint."
                    ),
                    frontend_call=call,
                )
            )
            return

        # Check for HTTP method match
        matching_method_routes = [r for r in matching_path_routes if r.method == call.method]
        if not matching_method_routes:
            expected_methods = [r.method.value for r in matching_path_routes]
            violations.append(
                CrossStackViolation(
                    code="I8:METHOD_MISMATCH",
                    message=(
                        f"Frontend call '{call.method.value} {call.raw_path}' in "
                        f"{call.file_path}:{call.line} uses invalid method. Expected: {expected_methods}"
                    ),
                    frontend_call=call,
                    matching_route=matching_path_routes[0],
                )
            )
            return

        # Check payload schema fields for POST/PUT/PATCH
        target_route = matching_method_routes[0]
        self._verify_payload_fields(call, target_route, violations)

    def _verify_payload_fields(
        self,
        call: FrontendCall,
        route: BackendRoute,
        violations: List[CrossStackViolation],
    ) -> None:
        """Checks if required backend request fields are supplied in frontend call."""
        if not route.required_fields or not call.payload_keys:
            # If backend requires fields and frontend supplies non-empty keys, verify subset
            if route.required_fields and not call.payload_keys and call.method in ("POST", "PUT", "PATCH"):
                violations.append(
                    CrossStackViolation(
                        code="I8:MISSING_REQUIRED_FIELD",
                        message=(
                            f"Frontend call to '{call.raw_path}' in {call.file_path}:{call.line} "
                            f"omits required request fields: {route.required_fields}"
                        ),
                        frontend_call=call,
                        matching_route=route,
                    )
                )
            return

        missing = [f for f in route.required_fields if f not in call.payload_keys]
        if missing:
            violations.append(
                CrossStackViolation(
                    code="I8:MISSING_REQUIRED_FIELD",
                    message=(
                        f"Frontend call to '{call.raw_path}' in {call.file_path}:{call.line} "
                        f"is missing required schema fields: {missing}"
                    ),
                    frontend_call=call,
                    matching_route=route,
                )
            )
