import uvicorn
from pydantic import BaseModel
from datetime import datetime
import requests
from bs4 import BeautifulSoup
import time
from getuseragent import UserAgent
from fastapi import FastAPI

app = FastAPI()

soup = ""


class Phishing(BaseModel):
    PhishTank_id: int
    url: str
    status: str
    is_online: str
    submitted_by: str
    date_created: datetime

    class Config:
        arbitrary_types_allowed = True
        from_attributes = True


def get_main_page(verified="y", active="y") -> int:
    global soup

    user_agent = UserAgent()
    the_user_agent = user_agent.Random()
    headers = {"User-agent": the_user_agent}

    url = f"https://phishtank.org/phish_search.php?verified={verified}&active={active}"

    response = requests.get(url, headers=headers)

    if response.status_code != 200:
        return 1

    html_text = response.text
    soup = BeautifulSoup(html_text, "lxml")

    return 0


def get_phishing_sites():
    get_main_page(verified="y", active="y")
    submission_list = get_submissions(verified="y")
    return submission_list


def get_submissions(verified="y"):
    if verified == "y":
        submissions = soup.find_all("tr", style="background: #ffffcc;")

    site_list = []
    for submission in submissions:
        site = get_site_object(submission)
        site_list.append(site)

    return site_list

site_counter = 0

def get_site_object(submission: BeautifulSoup, verified="y", active="y"):
    global site_counter  # Fonksiyon içinde sayaç değişkenini kullanabilmek için 'global' anahtar kelimesini kullanıyoruz

    values = submission.find_all("td", class_="value")

    Phishtank_id = int(values[0].find("a").text)
    url = values[1].find_next(string=True).strip()

    if verified == "y":
        status = "Valid"
    else:
        status = "Suspected"  # Burada Phishing.StatusEnum.SUSPECTED olacak şekilde düzeltilmelidir.

    if active == "y":
        is_online = "True"
    else:
        is_online = "False"  # Burada Phishing.IsOnlineEnum.FALSE olacak şekilde düzeltilmelidir.

    submitted_by = values[2].find("a").text

    site_id = site_counter + 1
    site_counter += 1




    site = Phishing(
        site_id=site_id,
        PhishTank_id=Phishtank_id,
        url=url,
        status=status,
        is_online=is_online,
        submitted_by=submitted_by,
        date_created=time.time(),
    )

    return site







@app.get("/")
async def list_phishing_sites():
    return get_phishing_sites()






if __name__ == "__main__":
    uvicorn.run(app, host="localhost", port=8000)
