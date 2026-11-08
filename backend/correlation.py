"""Deterministic alert grouping for short-lived, shared-entity activity."""

import os
from collections import defaultdict, deque
from datetime import datetime, timezone


ENTITY_FIELDS = {
    "host": (
        ("agent", "name"), ("host", "name"), ("data", "hostname"),
        ("hostname",),
    ),
    "user": (
        ("data", "srcuser"), ("data", "dstuser"), ("user", "name"),
        ("data", "user"), ("win", "eventdata", "targetUserName"),
    ),
    "source_ip": (
        ("data", "srcip"), ("source", "ip"), ("srcip",),
    ),
}


def correlation_window_minutes():
    """Read the bounded correlation window, defaulting to fifteen minutes."""
    raw_value = os.environ.get("SOC_AI_CORRELATION_WINDOW_MINUTES", "15")
    try:
        value = int(raw_value)
    except ValueError:
        raise ValueError("SOC_AI_CORRELATION_WINDOW_MINUTES must be an integer") from None
    if not 1 <= value <= 1440:
        raise ValueError("SOC_AI_CORRELATION_WINDOW_MINUTES must be between 1 and 1440")
    return value


def _nested_value(value, path):
    for part in path:
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


def _timestamp(alert):
    value = alert.get("@timestamp") or alert.get("timestamp")
    if not isinstance(value, str):
        raise ValueError("Every alert must include an ISO timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError("Every alert must include an ISO timestamp") from None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _entities(alert):
    entities = {}
    for kind, paths in ENTITY_FIELDS.items():
        for path in paths:
            value = _nested_value(alert, path)
            if isinstance(value, str) and value.strip():
                display_value = value.strip()
                entities[kind] = display_value
                break
    return entities


def _normalized_entities(entities):
    return {
        kind: value.strip().casefold()
        for kind, value in entities.items()
    }


def _rule_id(alert):
    rule = alert.get("rule")
    if isinstance(rule, dict):
        value = rule.get("id")
        if isinstance(value, (str, int)):
            return str(value)
    return "unknown"


def correlate_alerts(alerts, window_minutes=None):
    """Return connected groups whose alerts share an entity within the window.

    Pairwise shared-entity links form connected components, so a short sequence
    such as SSH failures, success, and sudo can be represented as one group.
    """
    if not isinstance(alerts, list) or len(alerts) > 500:
        raise ValueError("alerts must be a list containing at most 500 entries")
    window_minutes = window_minutes or correlation_window_minutes()
    if not isinstance(window_minutes, int) or not 1 <= window_minutes <= 1440:
        raise ValueError("Correlation window must be between 1 and 1440 minutes")

    events = []
    for index, alert in enumerate(alerts):
        if not isinstance(alert, dict):
            raise ValueError("Every alert must be an object")
        timestamp = _timestamp(alert)
        raw_id = alert.get("_id", alert.get("id"))
        alert_id = str(raw_id) if raw_id is not None else f"alert-{index + 1}"
        entities = _entities(alert)
        normalized = _normalized_entities(entities)
        rules = alert.get("rule") if isinstance(alert.get("rule"), dict) else {}
        description = rules.get("description", "")
        if not isinstance(description, str):
            description = ""
        events.append({
            "timestamp": timestamp,
            "alert_id": alert_id,
            "rule_id": _rule_id(alert),
            "description": description,
            "entities": entities,
            "normalized_entities": normalized,
        })

    events.sort(key=lambda event: (event["timestamp"], event["alert_id"]))
    adjacency = defaultdict(set)
    edge_entities = defaultdict(set)
    max_delta_seconds = window_minutes * 60
    for left_index, left in enumerate(events):
        for right_index in range(left_index + 1, len(events)):
            right = events[right_index]
            if (right["timestamp"] - left["timestamp"]).total_seconds() > max_delta_seconds:
                break
            shared = {
                (kind, value)
                for kind, value in left["normalized_entities"].items()
                if right["normalized_entities"].get(kind) == value
            }
            if shared:
                adjacency[left_index].add(right_index)
                adjacency[right_index].add(left_index)
                edge_entities[(left_index, right_index)].update(shared)

    groups = []
    visited = set()
    for start in sorted(adjacency):
        if start in visited:
            continue
        members = []
        pending = deque([start])
        visited.add(start)
        while pending:
            current = pending.popleft()
            members.append(current)
            for neighbor in sorted(adjacency[current]):
                if neighbor not in visited:
                    visited.add(neighbor)
                    pending.append(neighbor)
        member_set = set(members)
        shared_pairs = set()
        for (left, right), pairs in edge_entities.items():
            if left in member_set and right in member_set:
                shared_pairs.update(pairs)
        timeline = []
        for member in sorted(members, key=lambda item: (events[item]["timestamp"], events[item]["alert_id"])):
            event = events[member]
            timeline.append({
                "timestamp": event["timestamp"].isoformat().replace("+00:00", "Z"),
                "alert_id": event["alert_id"],
                "rule_ids": [event["rule_id"]],
                "description": event["description"],
                "entities": event["entities"],
            })
        groups.append({
            "group_id": f"correlation-{len(groups) + 1}",
            "alert_ids": [event["alert_id"] for event in timeline],
            "shared_entities": [
                {"type": kind, "value": value}
                for kind, value in sorted(shared_pairs)
            ],
            "timeline": timeline,
        })

    return {"window_minutes": window_minutes, "groups": groups}
