"""Deterministic template compiler: task text + user grants -> TaskScope.

An LLM parser may later propose a scope, but it can only narrow what the grants allow.
"""

from __future__ import annotations

import re

from .canon import clean_destination, fold
from .models import Classification, Op, TaskScope

_VERBS = [
    (r"\b(read|open|review|look at|list)\b", {Op.READ}),
    (r"\b(summari[sz]e|summary|digest)\b", {Op.READ, Op.SUMMARIZE}),
    (r"\b(write|save|create|draft)\b", {Op.WRITE}),
    (r"\b(email|e-mail|send|forward|reply)\b", {Op.SEND}),
    (r"\b(upload|publish|post)\b", {Op.UPLOAD}),
    (r"\b(query|database|sql|lookup)\b", {Op.QUERY}),
    (r"\b(run|execute|shell|command)\b", {Op.EXEC}),
]


GRANT_KEYS = {"resources", "destinations", "max_classification", "project_root", "ops"}


def validate_grants(grants: object) -> dict:
    """Refuse grants the engine would otherwise half-ignore: a wrong type, an unknown key (a typo such as `resource`),
    a bad classification or operation, or absurd sizes. Returns the grants as a dict."""
    if not isinstance(grants, dict):
        raise ValueError("grants must be an object")
    extra = set(grants) - GRANT_KEYS
    if extra:
        raise ValueError(f"unknown grant(s) {sorted(extra)}; known: {sorted(GRANT_KEYS)}")
    for key in ("resources", "destinations", "ops"):
        v = grants.get(key, [])
        if not isinstance(v, list) or len(v) > 200 or not all(isinstance(x, str) and len(x) <= 300 for x in v):
            raise ValueError(f"grants.{key} must be a list of at most 200 short strings")
    if grants.get("max_classification", "INTERNAL") not in Classification.__members__:
        raise ValueError(f"grants.max_classification must be one of {list(Classification.__members__)}")
    bad = [o for o in grants.get("ops", []) if o not in {o.value for o in Op}]
    if bad:
        raise ValueError(f"grants.ops: unknown operation(s) {bad}")
    root = grants.get("project_root")
    if root is not None and (not isinstance(root, str) or len(root) > 300):
        raise ValueError("grants.project_root must be a short string")
    return grants


def compile_scope(task: str, grants: dict) -> TaskScope:
    validate_grants(grants)
    ops: set[Op] = set()
    for pat, o in _VERBS:
        if re.search(pat, task, re.IGNORECASE):
            ops |= o
    if ops & {Op.SEND, Op.UPLOAD, Op.SUMMARIZE}:  # sending or summarizing implies reading the source
        ops.add(Op.READ)
    confidence = 1.0
    if not ops:  # unclear task -> least privilege, flag low confidence
        ops, confidence = {Op.READ}, 0.5
    granted = {Op(o) for o in grants.get("ops", [o.value for o in Op])}
    return TaskScope(
        task_text=task,
        allowed_ops=ops & granted,
        allowed_resources=[fold(r) for r in grants.get("resources", [])],  # compared case-insensitively
        allowed_destinations=[clean_destination(d)[0] for d in grants.get("destinations", [])],
        max_classification=Classification[grants.get("max_classification", "INTERNAL")],
        project_root=fold(grants["project_root"]) if grants.get("project_root") else None,
        confidence=confidence,
    )
