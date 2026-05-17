"""
tests/test_week4_response_automation.py - Response Automation Tests

Tests for:
- Playbook definition and management
- Response action creation
- Workflow execution and tracking
- Action history logging
- Metrics and reporting
"""

import pytest
from datetime import datetime, timedelta

from core.response_automation import (
    ResponseAutomationEngine,
    Playbook,
    ResponseAction,
    ResponseWorkflow,
    ActionStatus,
)


class TestResponseAction:
    """Test response actions."""

    def test_create_response_action(self):
        """Test creating response action."""
        action = ResponseAction("action-1", "block", "192.168.1.1")

        assert action.action_id == "action-1"
        assert action.action_type == "block"
        assert action.target == "192.168.1.1"
        assert action.status == ActionStatus.PENDING

    def test_action_to_dict(self):
        """Test action serialization."""
        action = ResponseAction("test-action", "alert", "campaign-1")
        action.result = "Success"
        action.status = ActionStatus.SUCCESS

        data = action.to_dict()

        assert data["action_id"] == "test-action"
        assert data["action_type"] == "alert"
        assert data["status"] == "success"

    def test_action_status_tracking(self):
        """Test action status tracking."""
        action = ResponseAction("track-action", "investigate", "actor-1")

        assert action.status == ActionStatus.PENDING
        action.status = ActionStatus.EXECUTING
        assert action.status == ActionStatus.EXECUTING
        action.status = ActionStatus.SUCCESS
        assert action.status == ActionStatus.SUCCESS


class TestPlaybook:
    """Test playbooks."""

    def test_create_playbook(self):
        """Test creating playbook."""
        playbook = Playbook("pb-1", "Campaign Response", "campaign")

        assert playbook.playbook_id == "pb-1"
        assert playbook.name == "Campaign Response"
        assert playbook.threat_type == "campaign"
        assert playbook.enabled is True

    def test_add_action_to_playbook(self):
        """Test adding actions to playbook."""
        playbook = Playbook("pb-actions", "Test Playbook", "campaign")
        action = ResponseAction("action-1", "block", "target-1")

        playbook.add_action(action)

        assert len(playbook.actions) == 1
        assert playbook.actions[0].action_type == "block"

    def test_playbook_to_dict(self):
        """Test playbook serialization."""
        playbook = Playbook("pb-dict", "Test", "actor")
        playbook.description = "Test playbook"

        data = playbook.to_dict()

        assert data["playbook_id"] == "pb-dict"
        assert data["name"] == "Test"
        assert data["threat_type"] == "actor"
        assert data["description"] == "Test playbook"

    def test_multiple_actions_in_playbook(self):
        """Test playbook with multiple actions."""
        playbook = Playbook("pb-multi", "Multi Action", "ioc")

        for i in range(5):
            action = ResponseAction(f"action-{i}", "block", f"ioc-{i}")
            playbook.add_action(action)

        assert len(playbook.actions) == 5


class TestResponseWorkflow:
    """Test response workflows."""

    def test_create_workflow(self):
        """Test creating workflow."""
        workflow = ResponseWorkflow("wf-1", "pb-1", "campaign-1", "campaign")

        assert workflow.workflow_id == "wf-1"
        assert workflow.playbook_id == "pb-1"
        assert workflow.threat_id == "campaign-1"
        assert workflow.status == "pending"

    def test_workflow_add_action(self):
        """Test adding actions to workflow."""
        workflow = ResponseWorkflow("wf-actions", "pb-1", "threat-1", "campaign")
        action = ResponseAction("action-wf", "alert", "target-1")

        workflow.add_action(action)

        assert len(workflow.actions) == 1

    def test_workflow_execute_action(self):
        """Test recording action execution."""
        workflow = ResponseWorkflow("wf-exec", "pb-1", "threat-1", "campaign")

        workflow.execute_action("action-1", "Success", True)
        assert workflow.success_count == 1

        workflow.execute_action("action-2", None, False)
        assert workflow.failure_count == 1

    def test_workflow_success_rate(self):
        """Test workflow success rate calculation."""
        workflow = ResponseWorkflow("wf-rate", "pb-1", "threat-1", "campaign")

        workflow.execute_action("action-1", "Success", True)
        workflow.execute_action("action-2", "Success", True)
        workflow.execute_action("action-3", None, False)

        assert workflow.get_success_rate() == pytest.approx(2/3, 0.01)

    def test_workflow_to_dict(self):
        """Test workflow serialization."""
        workflow = ResponseWorkflow("wf-dict", "pb-1", "threat-1", "campaign")
        workflow.status = "completed"
        workflow.execute_action("action-1", "Success", True)

        data = workflow.to_dict()

        assert data["workflow_id"] == "wf-dict"
        assert data["status"] == "completed"
        assert data["success_count"] == 1


class TestAutomationEngine:
    """Test automation engine."""

    def test_create_automation_engine(self):
        """Test creating automation engine."""
        engine = ResponseAutomationEngine()

        assert len(engine.playbooks) == 0
        assert len(engine.workflows) == 0

    def test_create_playbook(self):
        """Test creating playbook via engine."""
        engine = ResponseAutomationEngine()

        playbook = engine.create_playbook("pb-engine", "Test", "campaign", "Test playbook")

        assert playbook is not None
        assert "pb-engine" in engine.playbooks
        assert playbook.description == "Test playbook"

    def test_add_playbook_action(self):
        """Test adding action to playbook."""
        engine = ResponseAutomationEngine()
        engine.create_playbook("pb-action", "Test", "campaign")

        action = engine.add_playbook_action("pb-action", "block", "192.168.1.1", "Block IP")

        assert action is not None
        assert action.action_type == "block"

    def test_get_playbook(self):
        """Test retrieving playbook."""
        engine = ResponseAutomationEngine()
        engine.create_playbook("pb-get", "Test", "campaign")

        playbook = engine.get_playbook("pb-get")

        assert playbook is not None
        assert playbook.name == "Test"

    def test_execute_playbook(self):
        """Test executing playbook."""
        engine = ResponseAutomationEngine()
        engine.create_playbook("pb-exec", "Execute Test", "campaign")
        engine.add_playbook_action("pb-exec", "block", "ioc-1")
        engine.add_playbook_action("pb-exec", "alert", "campaign-1")

        workflow = engine.execute_playbook("pb-exec", "campaign-1", "campaign")

        assert workflow is not None
        assert len(workflow.actions) == 2
        assert workflow.status == "executing"

    def test_execute_workflow(self):
        """Test executing workflow actions."""
        engine = ResponseAutomationEngine()
        engine.create_playbook("pb-workflow", "Test", "campaign")
        engine.add_playbook_action("pb-workflow", "block", "target-1")

        workflow = engine.execute_playbook("pb-workflow", "threat-1", "campaign")
        results = engine.execute_workflow(workflow.workflow_id)

        assert "actions_executed" in results
        assert "actions_succeeded" in results
        assert results["actions_executed"] > 0

    def test_get_all_playbooks(self):
        """Test retrieving all playbooks."""
        engine = ResponseAutomationEngine()

        for i in range(3):
            engine.create_playbook(f"pb-all-{i}", f"Playbook {i}", "campaign")

        playbooks = engine.get_all_playbooks()

        assert len(playbooks) == 3
        assert all("playbook_id" in pb for pb in playbooks)

    def test_get_all_workflows(self):
        """Test retrieving all workflows."""
        engine = ResponseAutomationEngine()
        engine.create_playbook("pb-wf", "Test", "campaign")

        for i in range(2):
            workflow = engine.execute_playbook("pb-wf", f"threat-{i}", "campaign")
            engine.execute_workflow(workflow.workflow_id)

        workflows = engine.get_all_workflows()

        assert len(workflows) >= 2

    def test_action_history(self):
        """Test action history logging."""
        engine = ResponseAutomationEngine()
        engine.create_playbook("pb-history", "Test", "campaign")
        engine.add_playbook_action("pb-history", "block", "ioc-1")

        workflow = engine.execute_playbook("pb-history", "threat-1", "campaign")
        engine.execute_workflow(workflow.workflow_id)

        history = engine.get_action_history(limit=10)

        assert len(history) > 0


class TestMetrics:
    """Test automation metrics."""

    def test_workflow_metrics(self):
        """Test workflow metrics collection."""
        engine = ResponseAutomationEngine()
        engine.create_playbook("pb-metrics", "Test", "campaign")
        engine.add_playbook_action("pb-metrics", "block", "target-1")

        workflow = engine.execute_playbook("pb-metrics", "threat-1", "campaign")
        engine.execute_workflow(workflow.workflow_id)

        metrics = engine.get_workflow_metrics()

        assert "total_workflows" in metrics
        assert "completed_workflows" in metrics
        assert "avg_success_rate" in metrics
        assert "total_actions" in metrics

    def test_metrics_with_multiple_workflows(self):
        """Test metrics with multiple workflows."""
        engine = ResponseAutomationEngine()
        engine.create_playbook("pb-multi-metrics", "Test", "campaign")

        for i in range(3):
            engine.add_playbook_action("pb-multi-metrics", "block", f"ioc-{i}")

        for i in range(2):
            workflow = engine.execute_playbook("pb-multi-metrics", f"threat-{i}", "campaign")
            engine.execute_workflow(workflow.workflow_id)

        metrics = engine.get_workflow_metrics()

        assert metrics["total_workflows"] >= 2
        assert metrics["total_actions"] >= 3


class TestReporting:
    """Test automation reporting."""

    def test_automation_report(self):
        """Test complete automation report."""
        engine = ResponseAutomationEngine()
        engine.create_playbook("pb-report", "Test", "campaign")
        engine.add_playbook_action("pb-report", "block", "target-1")

        workflow = engine.execute_playbook("pb-report", "threat-1", "campaign")
        engine.execute_workflow(workflow.workflow_id)

        report = engine.get_automation_report()

        assert "timestamp" in report
        assert "playbooks" in report
        assert "workflows" in report
        assert "metrics" in report
        assert "recent_actions" in report

    def test_report_completeness(self):
        """Test report includes all components."""
        engine = ResponseAutomationEngine()
        engine.create_playbook("pb-complete", "Test", "campaign")
        engine.add_playbook_action("pb-complete", "alert", "target-1")

        report = engine.get_automation_report()

        assert len(report["playbooks"]) > 0
        assert "avg_success_rate" in report["metrics"]


class TestIntegration:
    """Test response automation integration."""

    def test_complete_automation_workflow(self):
        """Test complete automation workflow."""
        engine = ResponseAutomationEngine()

        # Create playbook
        engine.create_playbook("pb-complete", "Campaign Response", "campaign")
        engine.add_playbook_action("pb-complete", "block", "ioc-1")
        engine.add_playbook_action("pb-complete", "alert", "campaign-1")
        engine.add_playbook_action("pb-complete", "investigate", "actor-1")

        # Get playbook
        playbook = engine.get_playbook("pb-complete")
        assert len(playbook.actions) == 3

        # Execute workflow
        workflow = engine.execute_playbook("pb-complete", "threat-campaign-1", "campaign")
        results = engine.execute_workflow(workflow.workflow_id)

        # Verify results
        assert results["actions_executed"] == 3
        assert results["actions_succeeded"] > 0

        # Check history and metrics
        history = engine.get_action_history()
        assert len(history) > 0

        metrics = engine.get_workflow_metrics()
        assert metrics["completed_workflows"] >= 1

        # Get full report
        report = engine.get_automation_report()
        assert "workflows" in report
        assert len(report["workflows"]) >= 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
