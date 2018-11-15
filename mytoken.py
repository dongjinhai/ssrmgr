import config
import requests
import json
import logging


class MyToken(object):
    def __init__(self):
        self._username = config.TOKEN_USERNAME
        self._password = config.TOKEN_PASSWORD
        self.token = None
        if not self.token:
            self.token = self.access_token()

    def access_token(self):
        headers = {'Content-Type': 'application/json'}
        data = {
            'username': self._username,
            'password': self._password,
        }
        try:
            response = requests.post(r"{}/api/node/token/generate/".format(config.WEBAPI_DOMAIN),
                                     headers=headers,
                                     data=json.dumps(data),
                                     timeout=1)
            rest = response.json()
            if rest['result'] == 'success':
                return rest['access_token']
        except Exception as e:
            logging.error("请求token出错:{}".format(e))
        return None


token = MyToken()
# print(token.token)
print(token.token)
