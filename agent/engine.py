import json
from typing import List, Dict, Any
from pydantic import BaseModel
from .ocsf import OCSFEvent

class DetectionRule(BaseModel):
    id: str
    title: str
    description: str
    severity: str
    # Simplified Logic: {"class_uid": 1007, "conditions": {"process.name": "cmd.exe"}}
    logic: Dict[str, Any] 

class DetectionEngine:
    def __init__(self):
        self.rules: List[DetectionRule] = []
        self.findings: List[Dict[str, Any]] = []

    def load_rules(self, rules: List[DetectionRule]):
        self.rules = rules

    def evaluate(self, events: List[OCSFEvent]) -> List[Dict[str, Any]]:
        self.findings = []
        for event in events:
            for rule in self.rules:
                if self._match(event, rule):
                    finding = self._create_finding(event, rule)
                    self.findings.append(finding)
        return self.findings

    def _match(self, event: OCSFEvent, rule: DetectionRule) -> bool:
        logic = rule.logic
        
        # 1. Check Class UID
        if logic.get("class_uid") and event.class_uid != logic.get("class_uid"):
            return False
            
        # 2. Check Conditions (AND logic)
        conditions = logic.get("conditions", {})
        for field_path, expected_value in conditions.items():
            actual_value = self._get_field_value(event, field_path)
            
            # Simple operators
            if "__contains" in field_path:
                if not actual_value or expected_value.lower() not in str(actual_value).lower():
                    return False
            elif "__endswith" in field_path:
                if not actual_value or not str(actual_value).lower().endswith(expected_value.lower()):
                    return False
            elif "__startswith" in field_path:
                if not actual_value or not str(actual_value).lower().startswith(expected_value.lower()):
                    return False
            else:
                # Exact match (case-insensitive for strings)
                if isinstance(actual_value, str) and isinstance(expected_value, str):
                    if actual_value.lower() != expected_value.lower():
                        return False
                elif str(actual_value) != str(expected_value):
                    return False
                    
        return True

    def _get_field_value(self, event: OCSFEvent, field_path: str):
        # Handle "process.name" -> event.process.name
        # Handle "process.name__contains" -> event.process.name
        clean_path = field_path.split("__")[0]
        parts = clean_path.split(".")
        current = event
        try:
            for part in parts:
                if hasattr(current, part):
                    current = getattr(current, part)
                elif isinstance(current, dict):
                    current = current.get(part)
                else:
                    current = None
                    break
            
            if current is not None:
                return current
                
            # Fallback: Try actor.process if process is requested but not found
            if field_path.startswith("process.") and not field_path.startswith("actor."):
                return self._get_field_value(event, "actor." + field_path)
                
            return None
        except:
            return None

    def _create_finding(self, event: OCSFEvent, rule: DetectionRule):
        # Map OCSF to Alert format
        src = "Unknown"
        if event.src_endpoint:
            src = event.src_endpoint.ip or event.src_endpoint.hostname or "Unknown"
            
        target = "Unknown"
        if event.dst_endpoint:
            target = event.dst_endpoint.ip or event.dst_endpoint.hostname or "Unknown"
            
        details = f"Rule '{rule.title}' triggered. {rule.description}"
        if event.process:
            details += f" Process: {event.process.name} ({event.process.cmd_line})"
        if event.file:
            details += f" File: {event.file.name}"
            
        return {
            "type": rule.title,
            "source_ip": src,
            "target": target,
            "timestamp": event.timestamp,
            "details": details,
            "severity": rule.severity,
            "raw_event": event.dict()
        }
