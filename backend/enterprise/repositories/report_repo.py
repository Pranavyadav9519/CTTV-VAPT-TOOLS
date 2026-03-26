from typing import Optional
from sqlalchemy import select
from app.extensions import db
from app.models.report import Report


class ReportRepository:
    @staticmethod
    def add(report: Report) -> Report:
        with db.session.begin():
            db.session.add(report)
            db.session.flush()
            return report

    @staticmethod
    def get_by_report_id(report_id: str, tenant_id: str) -> Optional[Report]:
        stmt = select(Report).where(
            Report.report_id == report_id,
            Report.tenant_id == tenant_id,
            Report.is_deleted.is_(False),
        )
        return db.session.execute(stmt).scalars().first()
