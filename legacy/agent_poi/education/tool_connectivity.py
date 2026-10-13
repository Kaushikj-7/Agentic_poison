"""Educational Module 2: Tool Connectivity — Offline, Online & MCP in AGY.

Demonstrates:
1. Offline Deterministic Built-in Tools (SQLite, AST parsers, Regex rules).
2. Online Third-Party Tool Adapters (REST, Webhooks, Exponential Backoff, Circuit Breakers).
3. Model Context Protocol (MCP) Architecture in Antigravity (AGY).
"""

import json
import sqlite3
import time
from typing import Any, Dict
from agent_poi.education.foundational_agent_loop import BaseTool


# =============================================================================
# 1. Offline Deterministic Built-in Tool: Local SQLite Ledger
# =============================================================================

class OfflineDatabaseTool(BaseTool):
    """Zero-network, deterministic SQLite query tool for local data inspection."""

    name = "query_offline_database"
    description = "Queries the local SQLite database for customer or vendor accounts."

    def __init__(self):
        self.conn = sqlite3.connect(":memory:")
        self._init_db()

    def _init_db(self):
        cur = self.conn.cursor()
        cur.execute("CREATE TABLE accounts (id TEXT PRIMARY KEY, name TEXT, balance REAL, status TEXT)")
        cur.execute("INSERT INTO accounts VALUES ('ACC-01', 'Acme Logistics', 50000.0, 'VERIFIED')")
        cur.execute("INSERT INTO accounts VALUES ('ACC-02', 'Global Cloud Services', 120000.0, 'VERIFIED')")
        self.conn.commit()

    def get_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "account_id": {"type": "string", "description": "The account ID to query."}
            },
            "required": ["account_id"],
        }

    def execute(self, **kwargs) -> Dict[str, Any]:
        account_id = kwargs.get("account_id")
        cur = self.conn.cursor()
        cur.execute("SELECT name, balance, status FROM accounts WHERE id = ?", (account_id,))
        row = cur.fetchone()
        if row:
            return {
                "found": True,
                "account_id": account_id,
                "name": row[0],
                "account_name": row[0],
                "balance": row[1],
                "status": row[2],
            }
        return {"found": False, "error": f"Account {account_id} not found."}


# =============================================================================
# 2. Online Third-Party Tool Adapter: Simulated Resilient Gateway
# =============================================================================

class OnlinePaymentGatewayTool(BaseTool):
    """Simulated online REST client demonstrating production resilience patterns."""

    name = "execute_online_wire"
    description = "Dispatches a wire payment to an external banking API with circuit breaker."

    def __init__(self, max_retries: int = 3, failure_threshold: int = 3):
        self.max_retries = max_retries
        self.failure_threshold = failure_threshold
        self.consecutive_failures = 0
        self.circuit_open = False

    def get_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "recipient": {"type": "string"},
                "amount": {"type": "number"},
            },
            "required": ["recipient", "amount"],
        }

    def execute(self, **kwargs) -> Dict[str, Any]:
        if self.circuit_open:
            return {"status": "FAILED", "reason": "Circuit breaker OPEN: remote endpoint deemed unhealthy."}

        recipient = kwargs.get("recipient")
        amount = kwargs.get("amount", 0.0)

        for attempt in range(1, self.max_retries + 1):
            try:
                return self._simulate_http_post(recipient, amount)
            except IOError as e:
                self.consecutive_failures += 1
                if self.consecutive_failures >= self.failure_threshold:
                    self.circuit_open = True
                backoff = 0.01 * (2 ** (attempt - 1))
                time.sleep(backoff)

        return {"status": "FAILED", "reason": f"Max retries ({self.max_retries}) exceeded."}

    def _simulate_http_post(self, recipient: str, amount: float) -> Dict[str, Any]:
        if recipient == "FORCE_FAIL":
            raise IOError("Simulated 503 Service Unavailable")
        return {"status": "SUCCESS", "tx_id": f"TX-{int(time.time())}", "recipient": recipient, "amount": amount}


# =============================================================================
# 3. Model Context Protocol (MCP) Server Simulation
# =============================================================================

class MCPServerBridge:
    """Demonstrates MCP JSON-RPC protocol handling for local AGY tool servers."""

    def __init__(self):
        self._server_tools: Dict[str, BaseTool] = {
            "offline_db": OfflineDatabaseTool(),
            "online_pay": OnlinePaymentGatewayTool(),
        }

    def _handle_tools_list(self, req_id: Any) -> str:
        """Handle tools/list method."""
        tools_list = [
            {
                "name": name,
                "description": tool.description,
                "inputSchema": tool.get_schema(),
            }
            for name, tool in self._server_tools.items()
        ]
        return json.dumps({
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {"tools": tools_list},
        })

    def _handle_tools_call(self, req_id: Any, params: Dict[str, Any]) -> str:
        """Handle tools/call method."""
        tool_name = params.get("name")
        arguments = params.get("arguments", {})

        if tool_name not in self._server_tools:
            return json.dumps({
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32601, "message": f"Method/Tool '{tool_name}' not found"},
            })

        tool = self._server_tools[tool_name]
        result = tool.execute(**arguments)
        return json.dumps({
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {"content": [{"type": "text", "text": json.dumps(result)}]},
        })

    def handle_json_rpc(self, request_payload: str) -> str:
        """Handle incoming JSON-RPC 2.0 requests."""
        try:
            req = json.loads(request_payload)
            req_id = req.get("id")
            method = req.get("method")
            params = req.get("params", {})

            if method == "tools/list":
                return self._handle_tools_list(req_id)
            if method == "tools/call":
                return self._handle_tools_call(req_id, params)
            return json.dumps({
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32601, "message": f"Unknown method: {method}"},
            })
        except Exception as e:
            return json.dumps({
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32603, "message": f"Internal JSON-RPC error: {str(e)}"},
            })


# Educational compatibility alias for MCP client/server bridge
MCPProtocolClient = MCPServerBridge

