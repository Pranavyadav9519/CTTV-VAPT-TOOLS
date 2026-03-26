from typing import Optional
from sqlalchemy import select
from app.extensions import db
from app.models.scan import Scan


class ScanRepository:
    @staticmethod
    def add(scan: Scan) -> Scan:
        try:
            with db.session.begin():
                db.session.add(scan)
                db.session.flush()
            return scan
        except Exception as exc:
            db.session.rollback()
            raise RuntimeError(f"Failed to add scan: {exc}")

    @staticmethod
    def get_by_id(scan_id: int, tenant_id: str) -> Optional[Scan]:
        stmt = select(Scan).where(
            Scan.id == scan_id,
            Scan.tenant_id == tenant_id,
            Scan.is_deleted.is_(False),
        )
        try:
            return db.session.execute(stmt).scalars().first()
        except Exception as exc:
            raise RuntimeError(f"Failed to fetch scan: {exc}")

    @staticmethod
    def get_by_id_for_update(scan_id: int, tenant_id: str) -> Optional[Scan]:
        try:
            return (
                db.session.query(Scan)
                .with_for_update()
                .filter(
                    Scan.id == scan_id,
                    Scan.tenant_id == tenant_id,
                    Scan.is_deleted.is_(False),
                )
                .first()
            )
        except Exception as exc:
            raise RuntimeError(f"Failed to fetch scan for update: {exc}")

    @staticmethod
    def count_active_scans(tenant_id: str) -> int:
        try:
            return (
                db.session.query(Scan)
                .filter(
                    Scan.tenant_id == tenant_id,
                    Scan.status.in_(["pending", "queued", "running"]),
                    Scan.is_deleted.is_(False),
                )
                .count()
            )
        except Exception as exc:
            raise RuntimeError(f"Failed to count active scans: {exc}")
