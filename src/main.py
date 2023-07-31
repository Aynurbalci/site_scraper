import uvicorn
from src.database.phish_database import  SessionLocal
from src.api import phishtank_api
from src.database.phish_database import create_phishing_site,create_tables
if __name__ == "__main__":

    create_tables()

    phishing_sites = phishtank_api.get_phishing_sites()
    with SessionLocal() as db:
        for site in phishing_sites:
            create_phishing_site(db=db, site=site)


    uvicorn.run(phishtank_api.app, host="localhost", port=8000)
