"""
Assets API Router
Handles asset listing, filtering, inline ownership/criticality editing, and manual/CSV addition.
"""
from typing import List, Optional
from datetime import datetime, timezone
import csv
import io
from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile, File
from sqlalchemy.orm import Session

from ..db.session import get_db
from ..db.models import Asset, Scan
from ..schemas.schemas import AssetResponse, AssetBase, AssetUpdate

router = APIRouter(tags=["Assets"])

@router.get("/scans/{scan_id}/assets", response_model=List[AssetResponse])
def get_scan_assets(
    scan_id: str,
    asset_type: Optional[str] = Query(None, description="Filter by type (subdomain, ip, bucket)"),
    criticality: Optional[int] = Query(None, description="Filter by criticality 1-5"),
    search: Optional[str] = Query(None, description="Search domain, IP, or owner"),
    db: Session = Depends(get_db)
):
    query = db.query(Asset).filter(Asset.scan_id == scan_id)

    if asset_type:
        query = query.filter(Asset.type == asset_type.lower())
    if criticality:
        query = query.filter(Asset.criticality == criticality)
    if search:
        s = f"%{search.strip()}%"
        query = query.filter(
            (Asset.value.ilike(s)) | (Asset.owner.ilike(s)) | (Asset.ip_address.ilike(s)) | (Asset.asn.ilike(s))
        )

    return query.order_by(Asset.criticality.desc(), Asset.value.asc()).all()

@router.post("/scans/{scan_id}/assets", response_model=AssetResponse)
def add_manual_asset(
    scan_id: str,
    payload: AssetBase,
    db: Session = Depends(get_db)
):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    new_asset = Asset(
        scan_id=scan_id,
        type=payload.type,
        value=payload.value.strip(),
        source=payload.source or "Manual Entry",
        owner=payload.owner or "Unassigned",
        criticality=payload.criticality,
        ip_address=payload.ip_address,
        asn=payload.asn,
        technologies=payload.technologies,
        ports=payload.ports,
        tags=payload.tags,
        raw_metadata=payload.raw_metadata,
        first_seen=datetime.now(timezone.utc),
        last_seen=datetime.now(timezone.utc)
    )
    db.add(new_asset)
    db.commit()
    db.refresh(new_asset)

    # Update scan asset count
    scan.total_assets = db.query(Asset).filter(Asset.scan_id == scan_id).count()
    db.commit()

    return new_asset

@router.patch("/assets/{asset_id}", response_model=AssetResponse)
def update_asset(
    asset_id: int,
    payload: AssetUpdate,
    db: Session = Depends(get_db)
):
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    if payload.owner is not None:
        asset.owner = payload.owner.strip()
    if payload.criticality is not None:
        asset.criticality = payload.criticality
    if payload.tags is not None:
        asset.tags = payload.tags

    db.commit()
    db.refresh(asset)
    return asset

@router.post("/scans/{scan_id}/assets/csv")
async def import_assets_csv(
    scan_id: str,
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    content = await file.read()
    text = content.decode("utf-8", errors="replace")
    reader = csv.reader(io.StringIO(text))

    added_count = 0
    for row in reader:
        if not row:
            continue
        val = row[0].strip()
        if not val or val.lower() in ("value", "asset", "domain", "ip"):
            continue
        
        atype = row[1].strip() if len(row) > 1 and row[1].strip() else ("subdomain" if "." in val else "ip")
        owner = row[2].strip() if len(row) > 2 and row[2].strip() else "Unassigned"
        crit = int(row[3].strip()) if len(row) > 3 and row[3].strip().isdigit() else 3

        asset = Asset(
            scan_id=scan_id,
            type=atype,
            value=val,
            source="CSV Import",
            owner=owner,
            criticality=crit,
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc)
        )
        db.add(asset)
        added_count += 1

    db.commit()
    scan.total_assets = db.query(Asset).filter(Asset.scan_id == scan_id).count()
    db.commit()

    return {"message": f"Successfully imported {added_count} assets from CSV."}
