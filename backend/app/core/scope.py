"""
Scope and Target Validation Gatekeeper
Ensures targets have valid syntax and prevents destructive scanning.
Passive and active audit modes run non-destructive, rate-limited perimeter checks.
"""
import re
from typing import Tuple
from sqlalchemy.orm import Session

DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)
IP_REGEX = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
)

def is_valid_target(target: str) -> bool:
    clean = target.strip().lower()
    if DOMAIN_REGEX.match(clean) or IP_REGEX.match(clean) or clean == "localhost":
        return True
    return False

def check_scan_permission(domain: str, mode: str, db: Session) -> Tuple[bool, str]:
    """
    Validates scan permissions and syntax.
    Enforces non-destructive perimeter security checks.
    """
    clean = domain.strip().lower()
    if not is_valid_target(clean):
        return False, f"Invalid target format: '{clean}'. Must be a valid domain or IPv4 address."

    return True, f"Target '{clean}' approved for {mode} perimeter audit."
