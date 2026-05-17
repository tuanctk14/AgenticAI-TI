"""
core/response_automation.py - Response Automation Engine

Automated threat response workflows:
- Playbook definition and execution
- Automated response action orchestration
- Response workflow tracking and status
- Action logging and audit trail
- Response metrics and effectiveness
"""

from typing import Dict, List, Set, Optional, Any
from datetime import datetime, timedelta
from enum import Enum
import json


class ActionStatus(Enum):
    """Response action status."""
    PENDING = "pending"
    EXECUTING = "executing"
    SUCCESS = "success"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ResponseAction:
    """Individual response action."""

    def __init__(self, action_id: str, action_type: str, target: str):
        """Initialize response action.

        Args:
            action_id: Unique action identifier
            action_type: Type of action (block, alert, investigate, etc.)
            target: Target entity (IOC, campaign, actor, etc.)
        """
        self.action_id = action_id
        self.action_type = action_type
        self.target = target
        self.status = ActionStatus.PENDING
        self.created_at = datetime.utcnow()
        self.started_at = None
        self.completed_at = None
        self.result = None
        self.error_message = None
        self.metadata = {}

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "action_id": self.action_id,
            "action_type": self.action_type,
            "target": self.target,
            "status": self.status.value,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "result": self.result,
            "error_message": self.error_message,
        }


class Playbook:
    """Response playbook."""

    def __init__(self, playbook_id: str, name: str, threat_type: str):
        """Initialize playbook.

        Args:
            playbook_id: Unique playbook identifier
            name: Playbook name
            threat_type: Type of threat (campaign, actor, ioc)
        """
        self.playbook_id = playbook_id
        self.name = name
        self.threat_type = threat_type
        self.description = ""
        self.actions = []
        self.severity_levels = []
        self.created_at = datetime.utcnow()
        self.enabled = True

    def add_action(self, action: ResponseAction) -> None:
        """Add action to playbook.

        Args:
            action: ResponseAction to add
        """
        self.actions.append(action)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "playbook_id": self.playbook_id,
            "name": self.name,
            "threat_type": self.threat_type,
            "description": self.description,
            "action_count": len(self.actions),
            "severity_levels": self.severity_levels,
            "enabled": self.enabled,
        }


class ResponseWorkflow:
    """Response workflow execution."""

    def __init__(self, workflow_id: str, playbook_id: str, threat_id: str, threat_type: str):
        """Initialize response workflow.

        Args:
            workflow_id: Unique workflow identifier
            playbook_id: Associated playbook ID
            threat_id: Target threat ID
            threat_type: Type of threat
        """
        self.workflow_id = workflow_id
        self.playbook_id = playbook_id
        self.threat_id = threat_id
        self.threat_type = threat_type
        self.status = "pending"
        self.created_at = datetime.utcnow()
        self.started_at = None
        self.completed_at = None
        self.actions = []
        self.action_results = {}
        self.success_count = 0
        self.failure_count = 0

    def add_action(self, action: ResponseAction) -> None:
        """Add action to workflow.

        Args:
            action: ResponseAction to execute
        """
        self.actions.append(action)

    def execute_action(self, action_id: str, result: Any, success: bool) -> None:
        """Record action execution result.

        Args:
            action_id: Action ID that executed
            result: Result of action
            success: Whether action succeeded
        """
        self.action_results[action_id] = {
            "result": result,
            "success": success,
            "timestamp": datetime.utcnow(),
        }
        if success:
            self.success_count += 1
        else:
            self.failure_count += 1

    def get_success_rate(self) -> float:
        """Get workflow success rate.

        Returns:
            Success rate (0.0-1.0)
        """
        total = self.success_count + self.failure_count
        if total == 0:
            return 0.0
        return self.success_count / total

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "workflow_id": self.workflow_id,
            "playbook_id": self.playbook_id,
            "threat_id": self.threat_id,
            "threat_type": self.threat_type,
            "status": self.status,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "action_count": len(self.actions),
            "success_count": self.success_count,
            "failure_count": self.failure_count,
            "success_rate": self.get_success_rate(),
        }


class ResponseAutomationEngine:
    """Response automation and playbook execution engine."""

    def __init__(self):
        """Initialize response automation engine."""
        self.playbooks = {}
        self.workflows = {}
        self.action_history = []

    def create_playbook(
        self,
        playbook_id: str,
        name: str,
        threat_type: str,
        description: str = ""
    ) -> Playbook:
        """Create response playbook.

        Args:
            playbook_id: Unique playbook ID
            name: Playbook name
            threat_type: Type of threat
            description: Playbook description

        Returns:
            Created Playbook
        """
        playbook = Playbook(playbook_id, name, threat_type)
        playbook.description = description
        self.playbooks[playbook_id] = playbook
        return playbook

    def add_playbook_action(
        self,
        playbook_id: str,
        action_type: str,
        target: str,
        description: str = ""
    ) -> ResponseAction:
        """Add action to playbook.

        Args:
            playbook_id: Playbook ID
            action_type: Type of action
            target: Action target
            description: Action description

        Returns:
            Created ResponseAction
        """
        if playbook_id not in self.playbooks:
            return None

        action = ResponseAction(
            f"{playbook_id}-action-{len(self.playbooks[playbook_id].actions)}",
            action_type,
            target
        )
        action.metadata["description"] = description
        self.playbooks[playbook_id].add_action(action)
        return action

    def execute_playbook(self, playbook_id: str, threat_id: str, threat_type: str) -> ResponseWorkflow:
        """Execute response playbook.

        Args:
            playbook_id: Playbook to execute
            threat_id: Target threat ID
            threat_type: Type of threat

        Returns:
            ResponseWorkflow for tracking execution
        """
        if playbook_id not in self.playbooks:
            return None

        playbook = self.playbooks[playbook_id]
        workflow_id = f"workflow-{threat_id}-{datetime.utcnow().timestamp()}"
        workflow = ResponseWorkflow(workflow_id, playbook_id, threat_id, threat_type)
        workflow.status = "executing"
        workflow.started_at = datetime.utcnow()

        # Add actions from playbook to workflow
        for action in playbook.actions:
            workflow_action = ResponseAction(action.action_id, action.action_type, action.target)
            workflow_action.metadata = action.metadata.copy()
            workflow.add_action(workflow_action)

        self.workflows[workflow_id] = workflow
        return workflow

    def execute_workflow(self, workflow_id: str) -> Dict[str, Any]:
        """Execute response workflow.

        Args:
            workflow_id: Workflow to execute

        Returns:
            Execution results
        """
        if workflow_id not in self.workflows:
            return {"error": "Workflow not found"}

        workflow = self.workflows[workflow_id]
        results = {
            "workflow_id": workflow_id,
            "actions_executed": 0,
            "actions_succeeded": 0,
            "actions_failed": 0,
            "action_details": [],
        }

        for action in workflow.actions:
            action.status = ActionStatus.EXECUTING
            action.started_at = datetime.utcnow()

            # Simulate action execution
            success = self._execute_action(action)

            action.completed_at = datetime.utcnow()
            action.status = ActionStatus.SUCCESS if success else ActionStatus.FAILED

            if success:
                action.result = f"Action {action.action_type} executed on {action.target}"
                workflow.execute_action(action.action_id, action.result, True)
                results["actions_succeeded"] += 1
            else:
                action.error_message = f"Failed to execute {action.action_type} on {action.target}"
                workflow.execute_action(action.action_id, None, False)
                results["actions_failed"] += 1

            results["actions_executed"] += 1
            results["action_details"].append(action.to_dict())
            self.action_history.append(action)

        workflow.status = "completed"
        workflow.completed_at = datetime.utcnow()
        results["success_rate"] = workflow.get_success_rate()

        return results

    def _execute_action(self, action: ResponseAction) -> bool:
        """Execute individual response action.

        Args:
            action: ResponseAction to execute

        Returns:
            Whether action succeeded
        """
        # Simulate action execution - in real system, would connect to actual systems
        action_types = {
            "block": 0.95,  # 95% success rate
            "alert": 0.98,
            "investigate": 0.85,
            "contain": 0.90,
            "eradicate": 0.80,
            "recover": 0.85,
        }

        success_rate = action_types.get(action.action_type, 0.8)
        import random
        return random.random() < success_rate

    def get_playbook(self, playbook_id: str) -> Optional[Playbook]:
        """Get playbook by ID.

        Args:
            playbook_id: Playbook ID

        Returns:
            Playbook or None
        """
        return self.playbooks.get(playbook_id)

    def get_workflow(self, workflow_id: str) -> Optional[ResponseWorkflow]:
        """Get workflow by ID.

        Args:
            workflow_id: Workflow ID

        Returns:
            ResponseWorkflow or None
        """
        return self.workflows.get(workflow_id)

    def get_all_playbooks(self) -> List[Dict[str, Any]]:
        """Get all playbooks.

        Returns:
            List of playbook dicts
        """
        return [pb.to_dict() for pb in self.playbooks.values()]

    def get_all_workflows(self) -> List[Dict[str, Any]]:
        """Get all workflows.

        Returns:
            List of workflow dicts
        """
        return [wf.to_dict() for wf in self.workflows.values()]

    def get_action_history(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get action execution history.

        Args:
            limit: Maximum actions to return

        Returns:
            List of action records
        """
        return [action.to_dict() for action in self.action_history[-limit:]]

    def get_workflow_metrics(self) -> Dict[str, Any]:
        """Get workflow execution metrics.

        Returns:
            Dict with metrics
        """
        if not self.workflows:
            return {
                "total_workflows": 0,
                "completed_workflows": 0,
                "avg_success_rate": 0.0,
                "total_actions": 0,
                "successful_actions": 0,
            }

        completed = sum(1 for wf in self.workflows.values() if wf.status == "completed")
        total_actions = sum(len(wf.actions) for wf in self.workflows.values())
        successful_actions = sum(wf.success_count for wf in self.workflows.values())
        avg_success_rate = (
            successful_actions / total_actions if total_actions > 0 else 0.0
        )

        return {
            "total_workflows": len(self.workflows),
            "completed_workflows": completed,
            "avg_success_rate": avg_success_rate,
            "total_actions": total_actions,
            "successful_actions": successful_actions,
            "failed_actions": sum(wf.failure_count for wf in self.workflows.values()),
        }

    def get_automation_report(self) -> Dict[str, Any]:
        """Get comprehensive automation report.

        Returns:
            Dict with complete automation status
        """
        return {
            "timestamp": datetime.utcnow(),
            "playbooks": self.get_all_playbooks(),
            "workflows": self.get_all_workflows(),
            "metrics": self.get_workflow_metrics(),
            "recent_actions": self.get_action_history(limit=10),
        }
