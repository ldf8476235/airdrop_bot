import pyuseragents

from models import *
from noble_tls import Session, Client

class BlackPassAPI:
    API_URL = "https://nfq-api.thebeacon.gg/api"

    def __init__(self, account_data: Account):
        self.account = account_data
        self.session = self.setup_session()

        # if self.account.access_token:
        #     self.token_info = decode_id_token(self.account.access_token)
        #     # self.session.cookies.update(self.account.cookies)

    def setup_session(self) -> Session:
        session = Session(client=Client.CHROME_120)
        session.random_tls_extension_order = True

        session.timeout_seconds = 15
        session.headers = {
            "accept": "*/*",
            "accept-language": "en-US,en;q=0.9,ru;q=0.8",
            "origin": "https://blackpass.astranova.world",
            "referer": "https://blackpass.astranova.world/",
            "user-agent": pyuseragents.random(),
        }
        if self.account.access_token:
            session.headers['Authorization'] = 'Bearer ' + self.account.access_token
        session.proxies = {
            "http": self.account.proxy.as_url,
            "https": self.account.proxy.as_url,
        }
        return session