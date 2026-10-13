"""
Custom Detection Rules API Router
Enables users to manage declarative custom detection rules.
"""
from typing import List, Dict, Any
from fastapi import APIRouter, HTTPException, Body
from ..vuln.custom_rules_engine import get_all_custom_rules, add_custom_rule

router = APIRouter(prefix="/api/rules", tags=["rules"])


@router.get("/custom")
def list_custom_rules():
    """
    Returns all registered custom security detection rules.
    """
    return get_all_custom_rules()


@router.post("/custom")
def create_custom_rule(rule_payload: Dict[str, Any] = Body(...)):
    """
    Registers a new custom detection rule.
    """
    if "id" not in rule_payload or "name" not in rule_payload or "path" not in rule_payload:
        raise HTTPException(status_code=400, detail="Rule must specify 'id', 'name', and 'path'.")
    return add_custom_rule(rule_payload)
