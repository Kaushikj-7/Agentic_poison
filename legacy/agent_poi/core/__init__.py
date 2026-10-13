"""Core defense modules: CI decomposition, trust scoring, taint tracking, and task alignment."""

from agent_poi.core.ci_decomposer import CIDecomposer
from agent_poi.core.trust_scorer import TrustScorer
from agent_poi.core.taint_tracker import TaintTracker, AuthGraphDAG, AuthGraphNode
from agent_poi.core.alignment_gate import AlignmentGate, TaskShieldGate
from agent_poi.core.file_classifier import (
    FileClass,
    classify_file,
    audit_git_staging,
    audit_tracked_files,
    get_classification_report,
)

__all__ = [
    "CIDecomposer",
    "TrustScorer",
    "TaintTracker",
    "AuthGraphDAG",
    "AuthGraphNode",
    "AlignmentGate",
    "TaskShieldGate",
    "FileClass",
    "classify_file",
    "audit_git_staging",
    "audit_tracked_files",
    "get_classification_report",
]
