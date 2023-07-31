from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from src.configs.config import DB_USER,DB_PASSWORD,DB_HOST,DB_NAME,DB_PORT
from src.models.phish_models import Phishing
from sqlalchemy.orm import Session


DATABASE_URL = f"postgresql+psycopg2://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

engine = create_engine(DATABASE_URL)

SessionLocal = sessionmaker(autoflush=False, autocommit=False, bind=engine)

Base = declarative_base()

def create_phishing_site(db: Session, site: Phishing):
    existing_site = db.query(Phishing).filter(Phishing.PhishTank_id == site.PhishTank_id).first()
    if existing_site:
        return None

    db_site = Phishing(
        PhishTank_id=site.PhishTank_id,
        url=site.url,
        status=site.status,
        is_online=site.is_online,
        submitted_by=site.submitted_by,
        date_created=site.date_created
    )
    db.add(db_site)
    db.commit()
    db.refresh(db_site)
    return db_site


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def create_tables():
    Base.metadata.create_all(bind=engine)
