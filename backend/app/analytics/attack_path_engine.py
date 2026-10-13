"""
Attack Path & Blast Radius Topology Graph Engine
Constructs directed topological attack graphs:
Target Domain -> Discovered Subdomain -> Port / Service -> Vulnerability (CVE) -> Breach Exposure.
Highlights critical paths with CISA KEV weaponized vulnerabilities.
"""
from typing import Dict, Any, List
from sqlalchemy.orm import Session
from ..db.models import Scan, Asset, Finding

def generate_attack_path_graph(scan_id: str, db: Session) -> Dict[str, Any]:
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        return {"error": "Scan not found"}

    assets = db.query(Asset).filter(Asset.scan_id == scan_id).all()
    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()

    nodes = []
    edges = []

    # 1. Root Target Node (Level 0)
    root_id = "node-target-root"
    nodes.append({
        "id": root_id,
        "type": "target",
        "label": scan.target_domain,
        "sublabel": f"Root Apex Domain ({scan.company_name or 'Target'})",
        "level": 0,
        "severity": "Info",
        "is_critical_path": False
    })

    # 2. Asset Nodes (Level 1)
    asset_ids_in_graph = set()
    for a in assets:
        a_node_id = f"node-asset-{a.id}"
        asset_ids_in_graph.add(a.id)

        # Determine if asset has critical findings
        has_crit = any(f.asset_id == a.id and (f.severity == "Critical" or f.is_kev) for f in findings)

        nodes.append({
            "id": a_node_id,
            "type": "asset",
            "asset_type": a.type,
            "label": a.value,
            "sublabel": f"{a.type.upper()} • {a.ip_address or 'Cloud Managed'}",
            "level": 1,
            "severity": "Critical" if has_crit else "Low",
            "is_critical_path": has_crit,
            "ports": a.ports or []
        })

        edges.append({
            "source": root_id,
            "target": a_node_id,
            "label": "Resolves To",
            "is_critical": has_crit
        })

    # 3. Vulnerability Nodes (Level 2)
    vuln_nodes_count = 0
    critical_paths_count = 0

    for f in findings:
        f_node_id = f"node-vuln-{f.id}"
        is_crit = f.severity in ["Critical", "High"] or f.is_kev
        if is_crit:
            critical_paths_count += 1

        nodes.append({
            "id": f_node_id,
            "type": "vulnerability",
            "label": f.title[:35] + ("..." if len(f.title) > 35 else ""),
            "sublabel": f"{f.severity.upper()} • CVSS {f.cvss_score or 'N/A'}" + (" • CISA KEV" if f.is_kev else ""),
            "level": 2,
            "severity": f.severity,
            "is_kev": f.is_kev,
            "cvss": f.cvss_score,
            "fix_cost": f.estimated_fix_cost,
            "is_critical_path": is_crit,
            "cve_ids": f.cve_ids or []
        })
        vuln_nodes_count += 1

        # Connect from parent asset or root if no asset
        source_id = f"node-asset-{f.asset_id}" if (f.asset_id and f.asset_id in asset_ids_in_graph) else root_id
        edges.append({
            "source": source_id,
            "target": f_node_id,
            "label": "Exposes Flaw",
            "is_critical": is_crit
        })

    # 4. Breach Impact Node (Level 3)
    loss_val = float(scan.potential_breach_loss or 185000.0)
    impact_id = "node-impact-crown"
    nodes.append({
        "id": impact_id,
        "type": "impact",
        "label": f"Breach Exposure: ${loss_val:,.0f}",
        "sublabel": "Actuarial Annualized Loss Exposure",
        "level": 3,
        "severity": "Critical",
        "is_critical_path": critical_paths_count > 0
    })

    # Connect top high/critical vulnerabilities to the breach impact node
    for f in findings:
        if f.severity in ["Critical", "High"] or f.is_kev:
            edges.append({
                "source": f"node-vuln-{f.id}",
                "target": impact_id,
                "label": "Breach Conduit",
                "is_critical": True
            })

    return {
        "scan_id": scan_id,
        "target_domain": scan.target_domain,
        "nodes": nodes,
        "edges": edges,
        "metrics": {
            "total_nodes": len(nodes),
            "total_edges": len(edges),
            "critical_attack_paths": critical_paths_count,
            "potential_breach_loss": loss_val,
            "has_weaponized_conduit": any(f.is_kev for f in findings)
        }
    }
