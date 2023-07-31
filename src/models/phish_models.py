from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, String, DateTime
import datetime

Base = declarative_base()

class Phishing(Base):
    __tablename__ = "phishing_sites"

    site_id = Column(Integer, primary_key=True, autoincrement=True, index=True)
    PhishTank_id = Column(Integer, index=True)
    url = Column(String, nullable=False)
    status = Column(String, nullable=False)
    is_online = Column(String)
    submitted_by = Column(String, nullable=False)
    date_created = Column(DateTime, nullable=False, default=datetime.datetime.now)