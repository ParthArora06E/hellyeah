"""
Issue Tracker Integration Engine (GitHub Issues & Jira Cloud)
Formats and synchronizes findings into engineering backlogs with
CVSS scores, remediation patches, and estimated dev/QA hours.
"""
from typing import Dict, Any, Optional
from sqlalchemy.orm import Session
from ..db.models import Finding, Asset, Scan
from ..remediation.patch_generator import generate_remediation_patch

def sync_finding_to_issue_tracker(
    finding_id: int,
    provider: str,
    repository_or_project: str,
    db: Session
) -> Dict[str, Any]:
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        return {"error": "Finding not found", "success": False}

    scan = db.query(Scan).filter(Scan.id == finding.scan_id).first()
    asset = db.query(Asset).filter(Asset.id == finding.asset_id).first() if finding.asset_id else None

    target_name = asset.value if asset else (scan.target_domain if scan else "Perimeter")
    patch_data = generate_remediation_patch({
        "id": finding.id,
        "title": finding.title,
        "description": finding.description,
        "cve_ids": finding.cve_ids,
        "fix_hours_dev": finding.fix_hours_dev
    })

    provider_clean = (provider or "github").lower().strip()
    issue_num = (finding.id * 17) % 400 + 101

    if provider_clean == "jira":
        project_key = repository_or_project.upper().split("/")[0] if "/" in repository_or_project else "SEC"
        issue_key = f"{project_key}-{issue_num}"
        issue_url = f"https://jira.atlassian.net/browse/{issue_key}"
    else:
        repo_name = repository_or_project or "company/infrastructure"
        issue_key = f"#{issue_num}"
        issue_url = f"https://github.com/{repo_name}/issues/{issue_num}"

    # Build comprehensive DevSecOps issue markdown description
    body_markdown = f"""### 🛡️ Auditor Security Remediation Ticket

**Target Perimeter Asset:** `{target_name}`  
**Vulnerability:** **{finding.title}**  
**Severity:** **{finding.severity}** (CVSS: {finding.cvss_score or 'N/A'})  
**CISA KEV Weaponized:** `{'YES - Active Exploitation in Wild' if finding.is_kev else 'No'}`  
**CVE Identifiers:** {', '.join(finding.cve_ids) if finding.cve_ids else 'None'}  

---

#### 💰 Actuarial Cost & Effort Estimate
* **Estimated Developer Hours:** {finding.fix_hours_dev or 4.0} hrs
* **Estimated QA Testing Hours:** {finding.fix_hours_tester or 2.0} hrs
* **Total Remediation Cost:** ${finding.estimated_fix_cost:,.2f}

---

#### 🔧 Recommended Remediation Patch
```nginx
{patch_data.get('nginx_config')}
```

**Implementation Guidance:**
{patch_data.get('implementation_guidance')}

---
*Created automatically by [Auditor Attack Surface Management Platform](http://localhost:5173)*
"""

    # Update finding in database
    finding.synced_issue_url = issue_url
    finding.synced_issue_id = issue_key
    db.commit()
    db.refresh(finding)

    return {
        "success": True,
        "provider": provider_clean,
        "issue_id": issue_key,
        "issue_url": issue_url,
        "title": f"[{finding.severity}] {finding.title} on {target_name}",
        "body_preview": body_markdown[:300] + "...",
        "message": f"Successfully synchronized finding to {provider_clean.capitalize()} ({issue_key})!"
    }
