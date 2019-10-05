import hmac
import logging
import requests
import time
from datetime import datetime


class MotoClient:
    def __init__(self, host: str = "192.168.100.1"):
        self.logger = logging.getLogger(type(self).__name__)
        self.session = requests.Session()
        self.private_key = None
        self.host = host

    def login(self, username, password):
        # Request a challenge/uid/public key (this requires a valid username)
        request_data = {"Action": "request", "Username": username}
        response = self.hnap_request("Login", request_data)

        if response is None:
            self.logger.warn(
                "Failed to request login challenge, ensure host and username are correct"
            )
            return False

        self.session.cookies.set("uid", response["Cookie"])

        # Generate the private key from the public key/password/challenge
        self.private_key = (
            hmac.digest(
                (response["PublicKey"] + password).encode(),
                response["Challenge"].encode(),
                "md5",
            )
            .hex()
            .upper()
        )
        self.session.cookies.set("PrivateKey", self.private_key)

        # Generate the passphrase for logging in
        passphrase = (
            hmac.digest(
                self.private_key.encode(), response["Challenge"].encode(), "md5"
            )
            .hex()
            .upper()
        )

        request_data = {
            "Action": "login",
            "Username": username,
            "LoginPassword": passphrase,
        }
        response = self.hnap_request("Login", request_data)

        return response["LoginResult"] == "OK"

    def hnap_request(self, soap_action, data=None):
        """Send an HNAP (SOAP) request and unwrap the response

        Known HNAPs:
            GetMotoStatusSoftware
            GetMotoStatusStartupSequence
            GetMotoStatusConnectionInfo
            GetMotoStatusDownstreamChannelInfo
            GetMotoStatusUpstreamChannelInfo
            GetMotoLagStatus
            GetMotoStatusSecAccount
            GetMotoStatusLog
        """

        # Request parameters need to be wrapped in an object with the same name
        if data and soap_action not in data:
            data = {soap_action: data}

        soap_action_uri = f'"http://purenetworks.com/HNAP1/{soap_action}"'

        current_time = int(time.time())
        hnap_auth = (
            hmac.digest(
                (self.private_key or "withoutloginkey").encode(),
                f"{current_time}{soap_action_uri}".encode(),
                "md5",
            )
            .hex()
            .upper()
        )

        headers = {
            "SOAPAction": soap_action_uri,
            "HNAP_AUTH": f"{hnap_auth} {current_time}",
        }
        response = self.session.post(
            f"http://{self.host}/HNAP1/", headers=headers, json=data
        )

        try:
            result = response.json().get(f"{soap_action}Response")
            # Remove the result status from the response if it was OK
            if soap_action != "Login" and result[f"{soap_action}Result"] == "OK":
                del result[f"{soap_action}Result"]
        except:
            self.logger.warn("Failed to unwrap response: %s", response.text)
            result = None

        return result

    def software_info(self):
        return self.hnap_request("GetMotoStatusSoftware")

    def startup_sequence(self):
        return self.hnap_request("GetMotoStatusStartupSequence")

    def connection_info(self):
        return self.hnap_request("GetMotoStatusConnectionInfo")

    def downstream_info(self):
        channels = self.hnap_request("GetMotoStatusDownstreamChannelInfo")[
            "MotoConnDownstreamChannel"
        ].split("|+|")
        ds_keys = [
            "Channel",
            "Status",
            "Modulation",
            "ID",
            "Frequency",  # MHz
            "Power",  # dBmV
            "SNR",  # dB
            "Corrected",
            "Uncorrected",
        ]
        return [dict(zip(ds_keys, map(str.strip, c.split("^")))) for c in channels]

    def upstream_info(self):
        channels = self.hnap_request("GetMotoStatusUpstreamChannelInfo")[
            "MotoConnUpstreamChannel"
        ].split("|+|")
        us_keys = [
            "Channel",
            "Status",
            "Type",
            "ID",
            "Symbol Rate",  # Ksym/sec
            "Frequency",  # MHz
            "Power",  # dBmV
        ]
        return [dict(zip(us_keys, map(str.strip, c.split("^")))) for c in channels]

    def log_messages(self):
        messages = self.hnap_request("GetMotoStatusLog")["MotoStatusLogList"].split(
            "}-{"
        )
        message_keys = ["Time", "Date", "Priority", "Description"]
        return [dict(zip(message_keys, map(str.strip, m.split("^")))) for m in messages]


if __name__ == "__main__":
    c = MotoClient("192.168.100.1")

    if c.login("admin", "motorola"):
        print("connected")
    else:
        print("login failed")
