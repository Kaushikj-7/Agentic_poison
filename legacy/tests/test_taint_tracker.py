"""Unit tests for Provenance DAG and Ancestor Taint Tracking."""

from agent_poi.core.taint_tracker import TaintTracker
from agent_poi.memory.schema import SourceOrigin


def test_provenance_dag_taint_propagation():
    tracker = TaintTracker()

    # Register initial tainted node
    tracker.register_node(
        node_id="untrusted_web_01",
        origin=SourceOrigin.UNTRUSTED_WEB,
        direct_trust=0.20,
        final_trust=0.20,
    )

    # Register clean node
    tracker.register_node(
        node_id="clean_user_02",
        origin=SourceOrigin.VERIFIED_USER,
        direct_trust=0.95,
        final_trust=0.95,
    )

    # Child synthesized from both
    tracker.register_node(
        node_id="child_summary_03",
        origin=SourceOrigin.INTERNAL_TOOL,
        direct_trust=0.65,
        final_trust=0.40,
        parent_ids=["untrusted_web_01", "clean_user_02"],
    )

    # Check ancestry and taint detection
    ancestors = tracker.get_ancestors("child_summary_03")
    assert "untrusted_web_01" in ancestors
    assert "clean_user_02" in ancestors
    assert tracker.is_tainted_by("child_summary_03", taint_threshold=0.50) is True
