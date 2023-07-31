import whois
import socket
from geopy.geocoders import Nominatim
from urllib.parse import urlparse
from geopy.exc import GeocoderTimedOut, GeocoderUnavailable
from src.api.phishtank_api import get_phishing_sites
from fastapi import FastAPI, HTTPException
from src.configs.config import GOOGLE_SAFE_BROWSING_API_KEY
import requests
import json

app = FastAPI()

def get_domain_from_url(url):
    parsed_url = urlparse(url)
    return parsed_url.netloc

def get_whois_info(domain):
    try:
        whois_data = whois.whois(domain)
        return whois_data
    except Exception as e:
        print("Hata:", e)
        return None

def is_ssl_enabled(url):
    try:
        response = requests.get(url)
        return response.url.startswith("https")
    except requests.exceptions.RequestException:
        return False

def search_ioc_types(ioc_list, ioc_type):
    result = [ioc for ioc in ioc_list if ioc.get("type") == ioc_type]
    return result

def get_ioc_types(url):
    safebrowsing_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

    payload = {
        "client": {
            "clientId": "your-client-id",
            "clientVersion": "1.5.2",
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {GOOGLE_SAFE_BROWSING_API_KEY}",
    }

    response = requests.post(safebrowsing_url, json=payload, headers=headers)
    if response.ok:
        data = response.json()
        ioc_list = data.get("matches", [])
        ioc_types = set(ioc["threatType"] for ioc in ioc_list)
        return ioc_types
    return set()  # Return an empty set if the Safe Browsing API response is empty or not successful

def get_geometric_location(url):
    domain = get_domain_from_url(url)
    ip_address = socket.gethostbyname(domain)

    geolocator = Nominatim(user_agent="ioc")

    retries = 3
    for i in range(retries):
        try:
            location = geolocator.geocode(ip_address, language="en", timeout=5)
            if location:
                data = {
                    "url": url,
                    "ip_address": ip_address,
                    "latitude": location.latitude,
                    "longitude": location.longitude,
                    "address": location.address,
                }
                json_data = json.dumps(data)
                return json_data
            else:
                data = {
                    "url": url,
                    "ip_address": ip_address,
                    "error": "Geometric location not found for this IP address.",
                }
                json_data = json.dumps(data)
                return json_data
        except (GeocoderTimedOut, GeocoderUnavailable) as e:
            print(f"Geolocation request timed out or service unavailable. Retrying... (Attempt {i+1}/{retries})")
            continue
        except Exception as e:
            print(f"Failed to retrieve geolocation data for {url}. Error: {e}")
            return None

    print(f"Maximum retries reached. Failed to retrieve geolocation data for {url}.")
    return None

def is_blacklisted(url):
    safebrowsing_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

    payload = {
        "client": {
            "clientId": "your-client-id",
            "clientVersion": "1.5.2",
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {GOOGLE_SAFE_BROWSING_API_KEY}",
    }

    response = requests.post(safebrowsing_url, json=payload, headers=headers)
    if response.ok:
        data = response.json()
        if "matches" in data and data["matches"]:
            return True
    return False

def malicious_control(url):
    domain = get_domain_from_url(url)
    whois_info = get_whois_info(domain)

    if whois_info:
        print(f"URL: {url}")
        print(f"Domain: {domain}")
        print(f"WHOIS Information: {whois_info}")

        creation_date = whois_info.get("creation_date")
        expiration_date = whois_info.get("expiration_date")

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]

        if creation_date and expiration_date:
            if (expiration_date - creation_date).days < 365:
                print("Bu domain yeni oluşturulmuş ve hala geçerli. Zararlı olabileceği düşünülebilir.")
            else:
                print("Domain normal görünüyor.")
        else:
            print("WHOIS bilgilerinde eksik tarihler var. Zararlı kontrolü yapılamıyor.")
    else:
        print(f"Failed to retrieve WHOIS information for {domain}")

    ssl_enabled = is_ssl_enabled(url)
    print(f"SSL Enabled: {ssl_enabled}")

    ioc_types = get_ioc_types(url)
    if ioc_types:
        print("IoC Types:")
        for ioc_type in ioc_types:
            print(f"- {ioc_type}")
    else:
        print("No IoC Types found for this URL")

    geolocation_data = get_geometric_location(url)
    print(f"Geolocation Data: {geolocation_data}")


@app.get("/search")
def search_ioc_types(url: str):
    if not url.startswith("http://") and not url.startswith("https://"):
        raise HTTPException(status_code=400, detail="Invalid URL format. Please include 'http://' or 'https://'.")

    phishing_sites = get_phishing_sites()
    found = False
    for site in phishing_sites:
        if url == site.url:
            found = True
            break

    if found:
        ioc_types = get_ioc_types(url)
        if is_blacklisted(url):
            ioc_types.add("BLACKLISTED")

        domain = get_domain_from_url(url)
        whois_info = get_whois_info(domain)
        ssl_enabled = is_ssl_enabled(url)
        geolocation_data = get_geometric_location(url)

        return {

            "url": url,
            "domain": domain,
            "whois_info": whois_info,
            "ssl_enabled": ssl_enabled,

            "geolocation_data": geolocation_data,
            "is_blacklisted": is_blacklisted(url),  # is_blacklisted'ı da sonuçlar arasında gösterdik
        }
    else:
        return {"url": url, "message": "URL phishing sites listesinde bulunamadı"}

@app.get("/")
async def list_phishing_sites():
    return get_phishing_sites()
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
