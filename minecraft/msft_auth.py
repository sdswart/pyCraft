# yoink_token.py: pyCraft-compatible Microsoft account authentication
# https://gist.github.com/An0nDev/331c5052504ccf4919500632a9dd6237
from fastapi import FastAPI, Response, status
import json
import urllib.parse
import uuid
from typing import Optional
import os.path
import uvicorn  # pip install uvicorn
import time
import threading
import requests  # pip install requests
import minecraft.authentication  # part of pyCraft

# use the following function:
# def get_mc_auth_token (*, force_use_new_msft_account: bool = False, force_regenerate_mc_client_token: bool = False) -> minecraft.authentication.AuthenticationToken:
# and DO NOT forget to fill in the constants below

# When you import this file make sure to create an instance of the class to access the get_mc_auth_token function
# something like this
# from yoink_token import MinecraftToken
# token = MinecraftToken()
# access_token = token.get_mc_auth_token()

# based on https://wiki.vg/Microsoft_Authentication_Scheme and https://wiki.vg/Authentication (for client token desc)

# YOU HAVE TO FILL THESE IN WITH AN AZURE APP
# follow https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app

# App web service
# ssh -i ~/.ssh/id_rsa stephen@20.151.115.126

client_id = "6864c593-a9d2-4685-a668-5036c9e229d9"  # uuid
# SYM8Q~GuRE5521L4UglhDUKCMdNkjxh~SSfPQbiP
client_secret = "56b4dfbc-e36d-48ac-8897-e564f680613c"  # url-safe string

port = 8080  # web server port
host = "127.0.0.1"  # web server host, (used to retrieve the code from the url)
# redirect_uri = f"http://{host}:{port}/"
redirect_uri = f'https://pycraftauth.canadacentral.cloudapp.azure.com:{port}/'

bearer_token_file = "msft_bearer_token.txt"
client_token_file = "mc_client_token.txt"
save_file = "msft_refresh_token.txt"


url_base = "https://login.live.com/oauth20_{}.srf"


def create_server():
    app = FastAPI()

    @app.get("/", status_code=200)
    def root(response: Response, code: str | None = None):
        if code is None:
            if os.path.exists(bearer_token_file):
                with open(bearer_token_file, "r") as f:
                    bearer_token = f.read()
                return bearer_token
            else:
                response.status_code = status.HTTP_404_NOT_FOUND
                return 'No bearer_token found'
        else:
            with open(bearer_token_file, "w") as f:
                f.write(code)
            return code

    @app.get("/health/", status_code=200)
    def root():
        return {'msg': 'running'}

    return app


class MinecraftToken:
    def __init__(self) -> None:
        self.bearer_token = None

    def authenticate_with_msft(self) -> (str, str):
        auth_url_query = {
            "client_id": client_id,
            "response_type": "code",
            "redirect_uri": redirect_uri,  # just needs to be an inaccessible url so the user can yoink the token
        }
        auth_url = f"{url_base.format('authorize')}?{urllib.parse.urlencode(auth_url_query)}&scope=XboxLive.signin%20offline_access"
        print(f"Login to Microsoft account at:\n{auth_url}")

        while self.bearer_token is None:
            self.get_bearer_token()
            time.sleep(0.5)

        return self._make_msft_token_resp(code=self.bearer_token, grant_type="authorization_code")

    def get_bearer_token(self):
        res = requests.get(redirect_uri)
        if res.status_code == 200:
            self.bearer_token = res.text
            print(f'Got bearer_token: {self.bearer_token}')

    def reauthenticate_with_msft(self, *, refresh_token: str) -> (str, str):
        return self._make_msft_token_resp(refresh_token=refresh_token, grant_type="refresh_token")

    def _get_from_json(self, resp: requests.Response, *items: str):
        return map(resp.json().__getitem__, items)

    def _check_resp(self, resp: requests.Response):
        try:
            resp.raise_for_status()
        except:
            print(resp.text)
            raise

    def _json_req(self, url: str, data: Optional[dict] = None, *, auth_token: Optional[str] = None) -> dict:
        req_headers = {"Accept": "application/json"}
        if auth_token is not None: req_headers["Authorization"] = f"Bearer {auth_token}"
        function_call_kwargs = {}
        meth = "post" if data is not None else "get"
        if data is not None:
            req_headers["Content-Type"] = "application/json"
            function_call_kwargs["data"] = json.dumps(data).encode()
        function_call_kwargs["headers"] = req_headers
        resp = getattr(requests, meth)(url, **function_call_kwargs)
        self._check_resp(resp)
        return resp.json()

    def _make_msft_token_resp(self, *, code: Optional[str] = None, refresh_token: Optional[str] = None,
                              grant_type: str) -> (str, str):
        pass
        token_url_query = {
            "client_id": client_id,
            "client_secret": client_secret,
            "grant_type": grant_type,
            "redirect_uri": redirect_uri
        }
        if code is not None:
            token_url_query["code"] = code
        elif refresh_token is not None:
            token_url_query["refresh_token"] = refresh_token
        else:
            raise Exception("need either code or refresh_token")
        token_resp = requests.post(f"{url_base.format('token')}",
                                   headers={"Content-Type": "application/x-www-form-urlencoded"},
                                   data=urllib.parse.urlencode(token_url_query).encode())
        self._check_resp(token_resp)
        return self._get_from_json(token_resp, "access_token", "refresh_token")

    def get_mc_auth_token(self, *, force_use_new_msft_account: bool = False,
                          force_regenerate_mc_client_token: bool = False) -> minecraft.authentication.AuthenticationToken:
        if (not os.path.exists(save_file)) or force_use_new_msft_account:
            msft_access_token, msft_refresh_token = self.authenticate_with_msft()
        else:
            with open(save_file, "r") as f:
                msft_refresh_token = f.read()
            msft_access_token, msft_refresh_token = self.reauthenticate_with_msft(refresh_token=msft_refresh_token)

        with open(save_file, "w") as f:
            f.write(msft_refresh_token)

        xbl_req_json = {
            "Properties": {
                "AuthMethod": "RPS",
                "SiteName": "user.auth.xboxlive.com",
                "RpsTicket": f"d={msft_access_token}"
            },
            "RelyingParty": "http://auth.xboxlive.com",
            "TokenType": "JWT"
        }
        xbl_resp = self._json_req("https://user.auth.xboxlive.com/user/authenticate", xbl_req_json)
        xbl_token: str = xbl_resp["Token"]
        xbl_userhash: str = xbl_resp["DisplayClaims"]["xui"][0]["uhs"]

        xsts_req_json = {
            "Properties": {
                "SandboxId": "RETAIL",
                "UserTokens": [
                    xbl_token
                ]
            },
            "RelyingParty": "rp://api.minecraftservices.com/",
            "TokenType": "JWT"
        }
        xsts_resp = self._json_req("https://xsts.auth.xboxlive.com/xsts/authorize", xsts_req_json)
        xsts_token: str = xsts_resp["Token"]
        xsts_userhash: str = xsts_resp["DisplayClaims"]["xui"][0]["uhs"]
        assert xbl_userhash == xsts_userhash

        mc_auth_req_json = {"identityToken": f"XBL3.0 x={xbl_userhash};{xsts_token}"}
        mc_auth_resp = self._json_req("https://api.minecraftservices.com/authentication/login_with_xbox",
                                      mc_auth_req_json)
        mc_access_token: str = mc_auth_resp["access_token"]

        mc_ownership_check_resp = self._json_req("https://api.minecraftservices.com/entitlements/mcstore",
                                                 auth_token=mc_access_token)
        if not any(map(lambda item_name: item_name.endswith("minecraft"),
                       map(lambda item: item["name"], mc_ownership_check_resp["items"]))): raise Exception(
            "account does not own minecraft!")

        mc_profile = self._json_req("https://api.minecraftservices.com/minecraft/profile", auth_token=mc_access_token)
        mc_uuid = mc_profile["id"]
        mc_username = mc_profile["name"]

        if (not os.path.exists(client_token_file)) or force_regenerate_mc_client_token:
            client_token = uuid.uuid4().hex
            with open(client_token_file, "w") as f:
                f.write(client_token)
        else:
            with open(client_token_file, "r") as f:
                client_token = f.read()

        auth_token = minecraft.authentication.AuthenticationToken(username=mc_username, access_token=mc_access_token,
                                                                  client_token=client_token)
        auth_token.profile = minecraft.authentication.Profile(id_=mc_uuid, name=mc_username)

        return auth_token


if __name__ == "__main__":
    app = create_server()
    print('Running server...')
    uvicorn.run(app, host=host, port=port, log_level="error")
