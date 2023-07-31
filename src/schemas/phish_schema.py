from pydantic import BaseModel
from datetime import datetime


class PhishingBaseSchema(BaseModel):
    PhishTank_id: int
    url: str
    status: str
    is_online: str
    submitted_by: str
    date_created: datetime

    class Config:
        arbitrary_types_allowed = True
        from_attributes = True

