"""
core/ati_integration_layer.py - Integration Layer for LangGraph Agents

Cung cấp:
- Unified access to all ATI components
- Security enforcement (RBAC, auth)
- User context injection
- Audit logging
- Hybrid GraphRAG coordination
"""

from typing import Optional, Dict, Any
from datetime import datetime
import json

from core.authentication import AuthenticationService
from core.user_memory import UserMemoryEngine
from core.session_manager import SessionManager
from core.rbac_manager import RBACManager
from core.audit_logger import AuditLogger
from core.hybrid_graphrag_engine import HybridGraphRAGEngine


class ATIIntegrationLayer:
    """Unified ATI interface for LangGraph agents"""

    def __init__(self, db_path: str = "data/threat_knowledge.db"):
        """Khởi tạo integration layer"""
        self.db_path = db_path

        # Initialize all components
        self.auth_service = AuthenticationService(db_path)
        self.user_memory = UserMemoryEngine(db_path)
        self.session_manager = SessionManager(db_path)
        self.rbac_manager = RBACManager(db_path)
        self.audit_logger = AuditLogger(db_path)
        self.graphrag_engine = HybridGraphRAGEngine(db_path=db_path)

    # ──── Authentication ──────────────────────────────────────────────

    def register_user(self, username: str, password: str, email: str) -> Dict[str, Any]:
        """Register new user"""
        success, user_id, error = self.auth_service.register_user(username, password, email)

        if success:
            # Create user profile
            self.user_memory.create_user_profile(user_id)
            # Assign analyst role by default
            self.rbac_manager.assign_role_to_user(user_id, "analyst", "system")

            return {
                "success": True,
                "user_id": user_id,
                "message": "User created successfully"
            }
        else:
            return {
                "success": False,
                "error": error
            }

    def login(self, username: str, password: str, ip_address: str = "unknown") -> Dict[str, Any]:
        """Login user"""
        success, result, error = self.auth_service.login(username, password, ip_address)

        if success:
            # Log authentication
            self.audit_logger.log_authentication(
                user_id=result["user_id"],
                auth_type="password",
                success=True,
                ip_address=ip_address,
                user_agent="cli"
            )

            # Create user profile if not exists
            profile = self.user_memory.get_user_profile(result["user_id"])
            if not profile:
                self.user_memory.create_user_profile(result["user_id"])

            return {
                "success": True,
                "token": result["token"],
                "user_id": result["user_id"],
                "username": result["username"],
                "role": result["role"]
            }
        else:
            self.audit_logger.log_authentication(
                user_id=username,
                auth_type="password",
                success=False,
                ip_address=ip_address,
                user_agent="cli",
                reason=error
            )

            return {
                "success": False,
                "error": error
            }

    def validate_auth(self, token: str) -> Dict[str, Any]:
        """Validate JWT token"""
        valid, payload, error = self.auth_service.validate_token(token)

        if valid:
            return {
                "valid": True,
                "user_id": payload.get("user_id"),
                "username": payload.get("username"),
                "role": payload.get("role")
            }
        else:
            return {
                "valid": False,
                "error": error
            }

    # ──── User Context ────────────────────────────────────────────────

    def get_user_context(self, user_id: str, token: str) -> Dict[str, Any]:
        """
        Get full user context for agent reasoning

        Includes:
        - User profile
        - Recent investigations
        - Conversation history
        - User preferences
        - RBAC permissions
        """
        # Validate token
        valid, payload, error = self.auth_service.validate_token(token)
        if not valid:
            return {"error": "Invalid token"}

        if payload.get("user_id") != user_id:
            return {"error": "Token user mismatch"}

        context = {
            "user_id": user_id,
            "timestamp": datetime.utcnow().isoformat(),
            "profile": self.user_memory.get_user_profile(user_id),
            "role": payload.get("role"),
            "permissions": self.rbac_manager.get_user_permissions(user_id),
            "recent_context": self.user_memory.get_recent_context(user_id),
            "sessions": self.session_manager.get_user_sessions(user_id)
        }

        return context

    # ──── Investigation Management ────────────────────────────────────

    def create_investigation(
        self,
        user_id: str,
        title: str,
        investigation_type: str,
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Create new investigation (case)"""
        success, investigation_id, thread_id = self.user_memory.create_investigation(
            user_id, title, investigation_type, context
        )

        if success:
            # Log in audit
            self.audit_logger.log_investigation_created(
                user_id, investigation_id, investigation_type, title
            )

            return {
                "success": True,
                "investigation_id": investigation_id,
                "thread_id": thread_id
            }
        else:
            return {
                "success": False,
                "error": thread_id  # Error message
            }

    def add_conversation_message(
        self,
        user_id: str,
        thread_id: str,
        role: str,
        content: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Add message to conversation thread"""
        success, message_id = self.user_memory.add_message(
            thread_id, user_id, role, content, metadata
        )

        if success:
            return {
                "success": True,
                "message_id": message_id
            }
        else:
            return {
                "success": False,
                "error": message_id
            }

    def get_conversation_history(
        self,
        user_id: str,
        thread_id: str,
        limit: int = 50
    ) -> Dict[str, Any]:
        """Get conversation history for thread"""
        # Validate access
        if not self.user_memory.validate_access(user_id, thread_id, "thread"):
            return {"error": "Access denied"}

        messages = self.user_memory.get_conversation_history(thread_id, user_id, limit)

        return {
            "success": True,
            "thread_id": thread_id,
            "messages": messages
        }

    # ──── Tool Execution (with RBAC & Audit) ──────────────────────────

    def execute_tool(
        self,
        user_id: str,
        tool_name: str,
        parameters: Dict[str, Any],
        session_id: Optional[str] = None,
        ip_address: str = "unknown"
    ) -> Dict[str, Any]:
        """
        Execute tool with security checks

        Checks:
        1. Authentication (valid user)
        2. RBAC (user has permission)
        3. Audit logging
        """
        # Check RBAC
        if not self.rbac_manager.check_tool_access(user_id, tool_name):
            self.audit_logger.log_action(
                user_id=user_id,
                action="TOOL_EXECUTION_DENIED",
                resource_type="tool",
                resource_id=tool_name,
                resource_name=tool_name,
                status="failure",
                details={"reason": "insufficient_permissions"}
            )

            return {
                "success": False,
                "error": f"Permission denied for tool: {tool_name}"
            }

        # Execute tool (via LangGraph)
        # This would be replaced with actual tool execution
        import time
        start_time = time.time()

        try:
            # Tool execution would happen here
            # result = TOOLS_MAPPING[tool_name](**parameters)
            result = {
                "status": "success",
                "data": {"mock": "result"}
            }

            execution_time_ms = (time.time() - start_time) * 1000

            # Log execution
            self.audit_logger.log_tool_execution(
                user_id=user_id,
                tool_name=tool_name,
                parameters=parameters,
                result=result,
                execution_time_ms=execution_time_ms,
                session_id=session_id,
                ip_address=ip_address
            )

            # Log session activity
            if session_id:
                self.session_manager.log_session_activity(
                    session_id, user_id, f"TOOL_EXEC:{tool_name}", "tool", tool_name
                )

            return {
                "success": True,
                "result": result,
                "execution_time_ms": execution_time_ms
            }

        except Exception as e:
            execution_time_ms = (time.time() - start_time) * 1000

            self.audit_logger.log_tool_execution(
                user_id=user_id,
                tool_name=tool_name,
                parameters=parameters,
                result={"error": str(e)},
                execution_time_ms=execution_time_ms,
                session_id=session_id,
                ip_address=ip_address
            )

            return {
                "success": False,
                "error": str(e)
            }

    # ──── Hybrid GraphRAG ─────────────────────────────────────────────

    async def search_threat_intelligence(
        self,
        user_id: str,
        query: str,
        entity_types: Optional[list] = None,
        filters: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Hybrid GraphRAG search

        Combines:
        - Neo4j knowledge graph (primary)
        - SQLite threat memory (secondary)
        - Vector embeddings (tertiary)
        """
        result = await self.graphrag_engine.search_threat_intelligence(
            query=query,
            entity_types=entity_types,
            filters=filters,
            user_id=user_id
        )

        # Log retrieval
        self.audit_logger.log_action(
            user_id=user_id,
            action="GRAPHRAG_SEARCH",
            resource_type="search",
            resource_id=result.get("retrieval_id"),
            resource_name=query,
            details={
                "query": query,
                "confidence": result.get("confidence"),
                "execution_time_ms": result.get("execution_time_ms")
            }
        )

        return result

    # ──── Admin Operations ────────────────────────────────────────────

    def promote_user_to_admin(
        self,
        requesting_user_id: str,
        target_user_id: str
    ) -> Dict[str, Any]:
        """Promote user to admin (admin only)"""
        # Check requesting user is admin
        if not self.rbac_manager.is_admin(requesting_user_id):
            return {"success": False, "error": "Admin role required"}

        success, error = self.rbac_manager.assign_role_to_user(
            target_user_id, "admin", requesting_user_id
        )

        if success:
            self.audit_logger.log_action(
                user_id=requesting_user_id,
                action="PROMOTE_TO_ADMIN",
                resource_type="user",
                resource_id=target_user_id,
                resource_name=target_user_id,
                status="success"
            )

            return {"success": True}
        else:
            return {"success": False, "error": error}

    # ──── Compliance & Reporting ──────────────────────────────────────

    def get_audit_trail(
        self,
        user_id: str,
        limit: int = 100
    ) -> Dict[str, Any]:
        """Get audit trail for user"""
        return {
            "user_id": user_id,
            "audit_trail": self.audit_logger.get_user_audit_trail(user_id, limit)
        }

    def generate_compliance_report(
        self,
        start_date: datetime,
        end_date: datetime
    ) -> Dict[str, Any]:
        """Generate compliance report"""
        return {
            "report": self.audit_logger.generate_compliance_report(start_date, end_date)
        }
