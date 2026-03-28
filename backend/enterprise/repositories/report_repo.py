from typing import Optional
from sqlalchemy import select
from backend.enterprise.extensions import db
from backend.enterprise.models.report import Report


class ReportRepository:
    @staticmethod
    def add(report: Report) -> Report:
        db.session.add(report)
        db.session.commit()
        return report

    @staticmethod
    def get_by_report_id(report_id: str) -> Optional[Report]:
        stmt = select(Report).where(
            Report.report_id == report_id,
            Report.is_deleted.is_(False),
        )
        return db.session.execute(stmt).scalars().first()
