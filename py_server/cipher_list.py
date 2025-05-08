import requests
from bs4 import BeautifulSoup

res = requests.get("https://developers.cloudflare.com/ssl/edge-certificates/additional-options/cipher-suites/supported-cipher-suites/")

soup = BeautifulSoup(res.text, "html.parser")

tbody = soup.find("tbody")

cipher_suites = []

class CipherSuite:
    def __init__(self, name, version, description, number):
        self.name: str = name
        self.version: str = version.strip().split(" ")[1]
        self.Security: str = description
        self.number: str = number

for tr in tbody.find_all("tr"):
    tds = tr.find_all("td")
    cipher_suites.append(CipherSuite(tds[4].text, tds[1].text, tds[2].text, tds[3].text))

filtered = [_ for _ in cipher_suites if _.version == "1.2"]

print(filtered)
for i in filtered:
    number = i.number.replace("[", "").replace("]", "")
    print(f"{i.name} = {number},")
