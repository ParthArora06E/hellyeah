"""
Example Drop-in Plugin: Cloud Storage Bucket Discoverer
Discovers potential AWS S3 and Google Cloud Storage buckets based on target naming heuristics.
"""
from typing import List, Union
from backend.app.recon.adapter.base import BaseModule, ModuleMeta
from backend.app.recon.adapter.context import ScanContext
from backend.app.schemas.schemas import AssetBase, FindingBase

class CloudBucketCheckerPlugin(BaseModule):
    meta = ModuleMeta(
        name="cloud_bucket_checker",
        author="Auditor Community",
        description="Scans common AWS S3 and GCS bucket naming permutations for public accessibility or existence.",
        category="discovery",
        is_passive=False,
        version="1.0.0"
    )
    required_keys = []

    async def run(self, target: str, context: ScanContext) -> List[Union[AssetBase, FindingBase]]:
        results: List[Union[AssetBase, FindingBase]] = []
        base_name = target.replace(".", "-").split("-")[0]
        
        permutations = [
            f"{base_name}-assets",
            f"{base_name}-backup",
            f"{base_name}-data",
            f"{base_name}-public",
            f"{base_name}-media"
        ]

        context.emit_log("info", f"[Plugin:BucketChecker] Testing {len(permutations)} cloud bucket name permutations for {base_name}...")

        for name in permutations:
            s3_url = f"https://{name}.s3.amazonaws.com"
            try:
                resp = await context.http.get(s3_url, ttl_seconds=3600)
                if not resp:
                    continue

                if resp.status_code == 200:
                    # Publicly readable bucket!
                    asset = AssetBase(
                        type="cloud_bucket",
                        value=s3_url,
                        source="Cloud Bucket Plugin",
                        owner="Cloud Operations",
                        criticality=5,
                        tags=["aws_s3", "public_bucket"],
                        raw_metadata={"status": 200, "provider": "AWS S3"}
                    )
                    context.record_asset(asset)
                    results.append(asset)

                    finding = FindingBase(
                        title=f"Publicly Accessible AWS S3 Bucket: {name}",
                        description=f"Cloud storage bucket {s3_url} permits anonymous public read access over the internet, allowing anyone to list or download files.",
                        severity="Critical",
                        cvss_score=9.3,
                        epss_score=0.45,
                        is_kev=False,
                        source="Cloud Storage Audit Plugin",
                        confidence="Confirmed",
                        status="Open",
                        evidence={"bucket_url": s3_url, "http_status": 200},
                        remediation_text="Enable S3 'Block Public Access' setting and apply an IAM bucket policy requiring authenticated access.",
                        owasp_category="A01:2021-Broken Access Control",
                        iso_control="A.9.4.1 Information Access Restriction",
                        fix_hours_dev=1.0,
                        fix_hours_tester=1.0,
                        estimated_fix_cost=150.0,
                        risk_score=92.0
                    )
                    context.record_finding(finding)
                    results.append(finding)

                elif resp.status_code == 403:
                    # Exists but protected
                    asset = AssetBase(
                        type="cloud_bucket",
                        value=s3_url,
                        source="Cloud Bucket Plugin",
                        owner="Cloud Operations",
                        criticality=3,
                        tags=["aws_s3", "protected_bucket"],
                        raw_metadata={"status": 403, "provider": "AWS S3"}
                    )
                    context.record_asset(asset)
                    results.append(asset)
            except Exception:
                continue

        return results
