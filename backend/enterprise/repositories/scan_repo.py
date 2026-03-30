from typing import Optional
from sqlalchemy import select
from backend.enterprise.extensions import db
from backend.enterprise.models.scan import Scan, ScanStatus


class ScanRepository:
    @staticmethod
    def add(scan: Scan) -> Scan:
        try:
            db.session.add(scan)
            db.session.commit()
            return scan
        except Exception as exc:
            db.session.rollback()
            raise RuntimeError(f"Failed to add scan: {exc}")

    @staticmethod
    def get_by_id(scan_id: int) -> Optional[Scan]:
        stmt = select(Scan).where(
            Scan.id == scan_id,
            Scan.is_deleted.is_(False),
        )
        try:
            return db.session.execute(stmt).scalars().first()
        except Exception as exc:
            raise RuntimeError(f"Failed to fetch scan: {exc}")

    @staticmethod
    def get_by_id_for_update(scan_id: int) -> Optional[Scan]:
        try:
            return (
                db.session.query(Scan)
                .with_for_update()
                .filter(
                    Scan.id == scan_id,
                    Scan.is_deleted.is_(False),
                )
                .first()
            )
        except Exception as exc:
            raise RuntimeError(f"Failed to fetch scan for update: {exc}")

    @staticmethod
    def count_active_scans() -> int:
        try:
            return (
                db.session.query(Scan)
                .filter(
                    Scan.status.in_([ScanStatus.PENDING, ScanStatus.QUEUED, ScanStatus.RUNNING]),
                    Scan.is_deleted.is_(False),
                )
                .count()
            )
        except Exception as exc:
            raise RuntimeError(f"Failed to count active scans: {exc}")
