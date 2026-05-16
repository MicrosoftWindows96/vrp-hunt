"""Persistent JSON submission log."""

from __future__ import annotations

from datetime import date
from pathlib import Path

from vrp_hunt.tracking.models import StatusEvent, SubmissionLog, SubmissionRecord, SubmissionStatus


def default_tracking_path() -> Path:
    return Path.cwd() / "tracking" / "submissions.json"


class SubmissionStore:
    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path is not None else default_tracking_path()

    def load(self) -> SubmissionLog:
        if not self.path.exists():
            return SubmissionLog()
        return SubmissionLog.model_validate_json(self.path.read_text(encoding="utf-8"))

    def save(self, log: SubmissionLog) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(log.model_dump_json(indent=2), encoding="utf-8")

    def upsert(self, record: SubmissionRecord) -> SubmissionRecord:
        log = self.load()
        records = [item for item in log.records if item.submission_id != record.submission_id]
        records.append(record)
        self.save(SubmissionLog(records=records))
        return record

    def get(self, submission_id: str) -> SubmissionRecord:
        for record in self.load().records:
            if record.submission_id == submission_id:
                return record
        raise KeyError(submission_id)

    def update_status(
        self,
        submission_id: str,
        status: SubmissionStatus,
        *,
        changed_at: date,
        note: str | None = None,
    ) -> SubmissionRecord:
        record = self.get(submission_id)
        updated = record.model_copy(
            update={
                "status": status,
                "status_history": [
                    *record.status_history,
                    StatusEvent(status=status, changed_at=changed_at, note=note),
                ],
            }
        )
        self.upsert(updated)
        return updated
