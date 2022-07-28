import asyncio
import base64
from typing import Union, Any

import requests
from requests.cookies import RequestsCookieJar
from twocaptcha import TwoCaptcha

from types_qiwi.types import *


class SaveDict:
    phone, password = None, None
    web_qw = None
    ru_captcha_key = None


def _gen_headers():
    headers_sys = {
        'authority': 'edge.qiwi.com',
        'accept': 'application/json',
        'accept-language': 'ru',
        'authorization': f'TokenHeadV2 {SaveDict.web_qw}',
        'client-software': 'WEB v5.0.0',
        'content-type': 'application/json',
        'dnt': '1',
        'origin': 'https://qiwi.com',
        'referer': 'https://qiwi.com/',
        'sec-ch-ua': '".Not/A)Brand";v="99", "Google Chrome";v="103", "Chromium";v="103"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-site',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
                      'Chrome/103.0.0.0 Safari/537.36',
    }
    return headers_sys


def _gen_reg_platform():
    cookies = {
        'user_info': '1',
        'uxs_mig': '1',
        'uxs_uid': 'ed927e60-0d7c-11ed-92cb-578b411d6d00',
        'token-tail-checkout-oauth': '71a61735e8397729',
        'spa_upstream': 'af0376ede1e7ba4eed661170519eedd4',
        'token-tail': 'e1f6ab31b89d849d',
        'JSESSIONID': '64C7FB517FA6C2606E9AE0D2264E0843.node-s3242',
        'test.for.third.party.cookie': 'yes',
        'auth_ukafokfuabbuzdckyiwlunsh': 'MDI1fF98X3xcMQhGAm0EaV4Lb30Pf38zAkVkTgo'
                                         '2aHwgDHwUUXERVzw7XwJJZ'
                                         'HsMcQBXRltcdEtGDydDfkYCLkdQZVB7Y1BFWDBAEwc'
                                         '6VHdCVjp8WDR+YAJJKkVCYm9kfV57RwN0Qg==',
    }

    headers = {
        'authority': 'api.qiwi.com',
        'accept': 'application/json',
        'accept-language': 'ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7',
        'dnt': '1',
        'origin': 'https://api.qiwi.com',
        'referer': 'https://api.qiwi.com/main.action',
        'sec-ch-ua': '".Not/A)Brand";v="99", "Google Chrome";v="103", "Chromium";v="103"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-origin',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
                      'Chrome/103.0.0.0 Safari/537.36',
    }
    return cookies, headers


class Qiwi:
    accounts_obj = 'https://edge.qiwi.com/funding-sources/v2/persons/{0}/accounts'
    identifications_obj = 'https://edge.qiwi.com/identification/v4/persons/{0}/identifications'
    access_obj = 'https://edge.qiwi.com/qw-security-settings/v1/persons/{0}/settings'
    history_obj = 'https://edge.qiwi.com/payment-history/v2/persons/{0}/payments?rows={1}'
    me_obj = 'https://edge.qiwi.com/checkout-api/users/me?'
    p2p_key_obj = 'https://edge.qiwi.com/widgets-api/api/p2p/protected/keys/?'
    p2p_create_keys_obj = 'https://edge.qiwi.com/widgets-api/api/p2p/protected/keys/create'
    p2p_block_key_obj = 'https://edge.qiwi.com/widgets-api/api/p2p/protected/keys/block'
    p2p_create_invoice_obj = 'https://edge.qiwi.com/checkout-api/invoice/create'
    nickname_obj = 'https://edge.qiwi.com/qw-nicknames/v1/persons/{0}/nickname'
    email_obj = 'https://edge.qiwi.com/person-profile/v1/persons/{0}/email'
    confirm_email_obj = 'https://edge.qiwi.com/person-profile/v1/persons/{0}/email/confirm'
    create_account_obj = 'https://api.qiwi.com/oauth/authorize'
    start_verif_obj = 'https://edge.qiwi.com/qw-identification-applications/v1/persons/{' \
                      '0}/simple-identification-applications '

    def __init__(self, phone_number: [str, int, None], password: [str, None], qiwi_v2=None):
        SaveDict.password, SaveDict.phone = password, phone_number
        self.cookies = None
        self.widgetAliasCode = None

        self.captcha = TwoCaptcha(SaveDict.ru_captcha_key, server='rucaptcha.com')

        if not qiwi_v2:
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
            asyncio.set_event_loop(asyncio.new_event_loop())
            asyncio.run(self.save_account())
        else:
            SaveDict.web_qw = qiwi_v2.get('web-qw')
            x = RequestsCookieJar()
            cookies: dict = qiwi_v2.get('cookies')
            for ix in cookies:
                x.set(ix, cookies.get(ix))
            self.cookies = x

    async def save_account(self) -> bool:
        with requests.Session() as c:

            cookies = {
                'landing_count': '1',
                'user_info': '1',
                'JSESSIONID': 'D697DCE47D950298FAC789840CCAB139.node-s3253',
                'test.for.third.party.cookie': 'yes',
                'token-tail': 'a03100d182a041ce',
                'landing_name': 'qiwitoday',
                'auth_ukafokfuabbuzdckyiwlunsh': 'MDAyfF98X3wAV2IBSS17fmwlRlVxVVl1CXVkAFIvI38VYVxmL1l+C1AEAFd+e09sTEh'
                                                 'HV39aZ3J'
                                                 '+S20QC14CLGQRbioCXmAKWlN8A04seGdyJRNQdR4LewxxLAJPenNnS2xYZHdedQ==',
            }

            headers = {
                'authority': 'qiwi.com',
                'accept': 'application/json',
                'accept-language': 'ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7',
                'client-software': 'WEB v5.0.0',
                'dnt': '1',
                'origin': 'https://qiwi.com',
                'referer': 'https://qiwi.com/',
                'sec-ch-ua': '".Not/A)Brand";v="99", "Google Chrome";v="103", "Chromium";v="103"',
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': '"Windows"',
                'sec-fetch-dest': 'empty',
                'sec-fetch-mode': 'cors',
                'sec-fetch-site': 'same-origin',
                'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
                              'Chrome/103.0.0.0 Safari/537.36',
            }

            data = {
                'token_type': 'headtail',
                'grant_type': 'password',
                'client_id': 'web-qw',
                'client_secret': 'P0CGsaulvHy9',
                'anonymous_token_head': '8c482e59ae74e7e2',
                'username': f'+{str(SaveDict.phone)}',
                'password': f'{SaveDict.password}',
            }

            response = c.post('https://qiwi.com/oauth/token', cookies=cookies, headers=headers, data=data)
            result: dict = response.json()
            if result.get('error', None):
                err_text = result.get('user_message', None)
                exit(f'[!] Qiwi error: {err_text}')

            cookies = response.cookies
            self.cookies = cookies

            token1 = result.get('access_token', None)

            if not token1:
                return False

            qq = f'web-qw:{token1}'

            message_bytes = qq.encode('ascii')
            base64_bytes = base64.b64encode(message_bytes)
            base64_message = base64_bytes.decode('ascii')

            SaveDict.web_qw = base64_message

    def get_balance(self) -> Union[Accounts, int]:

        system_response = requests.get(Qiwi.accounts_obj.format(SaveDict.phone),
                                       headers=_gen_headers(), cookies=self.cookies)

        if system_response.ok:

            return Accounts(system_response.json())

        else:
            return system_response.status_code

    def get_identifications(self) -> Identifications:

        system_response = requests.get(Qiwi.identifications_obj.format(SaveDict.phone),
                                       headers=_gen_headers(), cookies=self.cookies)

        return Identifications(system_response.json())

    def get_available_access_methods(self):

        system_response = requests.get(Qiwi.access_obj.format(SaveDict.phone),
                                       headers=_gen_headers(), cookies=self.cookies)

        return Access(system_response.json())

    def create_p2p_keys(self, pair_name: str) -> NewPairP2p:

        json_data = {
            'keysPairName': f'{pair_name}',
        }

        system_response = requests.post(Qiwi.p2p_create_keys_obj,
                                        headers=_gen_headers(), cookies=self.cookies, json=json_data)

        return NewPairP2p(system_response.json())

    def get_my_p2p_keys(self) -> MyP2P_Keys:

        system_response = requests.get(Qiwi.p2p_key_obj,
                                       headers=_gen_headers(), cookies=self.cookies)

        return MyP2P_Keys(system_response.json())

    def block_p2p_key(self, public_key: str) -> bool:

        json_data = {
            'publicKey': f'{public_key}',
        }

        system_response = requests.post(Qiwi.p2p_block_key_obj,
                                        headers=_gen_headers(), cookies=self.cookies, json=json_data)
        if system_response.status_code == 500:
            return False
        else:
            return True

    def _gen_public_key_p2p(self) -> Union[bool, Any]:

        system_response = requests.post('https://edge.qiwi.com/widgets-api/api/p2p/protected/generate-public-key',
                                        headers=_gen_headers(), cookies=self.cookies)

        if system_response.status_code == 500:
            return False
        else:
            self.widgetAliasCode = system_response.json().get('widgetAliasCode')
            return system_response.json()

    def create_invoice(self, amount: int, comment: str = 'Qiwi Client By @cazqev') -> Union[bool, Any]:

        q: dict = self._gen_public_key_p2p()

        json_data = {
            'amount': amount,
            'extras': [
                {
                    'code': 'themeCode',
                    'value': self.widgetAliasCode,
                },
                {
                    'code': 'apiClient',
                    'value': 'p2p-admin',
                },
                {
                    'code': 'apiClientVersion',
                    'value': '0.17.0',
                },
            ],
            'comment': comment,
            'customers': [],
            'public_key': q.get('publicKey'),
        }

        system_response = requests.post(Qiwi.p2p_create_invoice_obj,
                                        headers=_gen_headers(), cookies=self.cookies, json=json_data)

        if system_response.status_code == 500:
            return False
        else:
            return system_response.json().get('invoice_uid')

    @property
    def get_my_input_form_url(self) -> str:
        return 'https://my.qiwi.com/{0}'.format(self.widgetAliasCode)

    def get_history(self, rows: int = 10) -> dict:
        system_response = requests.get(Qiwi.history_obj.format(SaveDict.phone, rows),
                                       headers=_gen_headers(), cookies=self.cookies)
        if system_response.ok:
            return system_response.json()
        else:
            exit(system_response.json())

    @property
    def get_my_token_v2(self):
        return SaveDict.web_qw

    @property
    def get_my_session(self):
        return self.cookies.get_dict()

    def set_rucaptcha(self, key: str):
        self.captcha.API_KEY = key

    def pay_to_nickname(self, nickname: str, amount: int, comment: str) -> dict:
        result = self.captcha.recaptcha(sitekey='6LczddIZAAAAADtx_azLKiG2CPqb6JvqYQorAqvG',
                                        url='https://qiwi.com/payment/form/99999',
                                        version='v3')

        json_data = {
            'id': '409790457665',
            'sum': {
                'amount': amount,
                'currency': '643',
            },
            'paymentMethod': {
                'accountId': '643',
                'type': 'Account',
            },
            'comment': comment,
            'fields': {
                'sinap-form-version': 'qw::99999, 5',
                'account': nickname,
                'accountType': 'nickname',
                'browser_user_agent_crc': 'c0c48336',
                'recaptcha3Value': result['code'],
            },
        }

        response = requests.post('https://edge.qiwi.com/qw-p2p-processing/v1/terms/99/payments', cookies=self.cookies,
                                 headers=_gen_headers(), json=json_data)

        return response.json()

    def get_nickname(self) -> Nickname:

        system_response = requests.get(Qiwi.nickname_obj.format(SaveDict.phone),
                                       headers=_gen_headers(), cookies=self.cookies)

        return Nickname(system_response.json())

    def gen_nickname(self) -> Nickname:

        json_data = {
            'type': 'GENERATE',
        }

        system_response = requests.put(Qiwi.nickname_obj.format(SaveDict.phone),
                                       headers=_gen_headers(), cookies=self.cookies, json=json_data)

        return Nickname(system_response.json())

    def create_nickname(self, nickname: str) -> Nickname:

        json_data = {
            'type': 'CUSTOM',
            'nickname': nickname
        }

        system_response = requests.put(Qiwi.nickname_obj.format(SaveDict.phone),
                                       headers=_gen_headers(), cookies=self.cookies, json=json_data)

        return Nickname(system_response.json())

    def get_email(self):
        system_response = requests.get(Qiwi.email_obj.format(SaveDict.phone),
                                       headers=_gen_headers(), cookies=self.cookies)

        return system_response.json()

    def add_email(self, email: str, change_password_via_email: bool = True, get_promos_to_email: bool = False):

        json_data = {"email": email,
                     "flags": {"USE_FOR_PROMO": get_promos_to_email, "USE_FOR_SECURITY": change_password_via_email},
                     "operationId": "602526688283"}

        system_response = requests.put(Qiwi.email_obj.format(SaveDict.phone),
                                       headers=_gen_headers(), cookies=self.cookies, json=json_data)

        return system_response.json()

    def confirm_email(self, code: [str, int]):

        json_data = {'code': code}
        system_response = requests.post(Qiwi.confirm_email_obj.format(SaveDict.phone),
                                        headers=_gen_headers(), cookies=self.cookies, json=json_data)

        return system_response.json().get('status')

    def create_account(self, phone_number: [str, int], logs: bool = False) -> Union[bool, Any]:
        if logs:
            print('[! CREATING !] Решение капчи')

        result = self.captcha.recaptcha(sitekey='6LfjX_4SAAAAAFfINkDklY_r2Q5BRiEqmLjs4UAC',
                                        url='https://api.qiwi.com/register/form.action?ref=newsite_index_1',
                                        version='v2')

        data = {
            'client_id': 'sso.qiwi.com',
            'response_type': 'urn:qiwi:oauth:response-type:confirmation-id',
            'username': f'+{str(phone_number)}',
            'recaptcha': result['code'],
        }

        session = requests.Session()
        if logs:
            print('[! CREATING !] Авторизация в Qiwi')

        get_confirmation_id = session.post('https://api.qiwi.com/oauth/authorize', cookies=_gen_reg_platform()[0],
                                           headers=_gen_reg_platform()[1], data=data)
        if get_confirmation_id.ok:
            return get_confirmation_id.json().get('confirmation_id')
        else:
            return False

    def submit_qiwi_reg(self, code: [str, int], confirmation_id: [str, int], phone: [str, int],
                        password: str) -> Union[bool, tuple[bytes, int], str]:

        data = {
            'client_id': 'sso.qiwi.com',
            'response_type': 'code',
            'username': f'+{str(phone)}',
            'vcode': f'{str(code)}',
            'confirmation_id': f'{str(confirmation_id)}',
        }

        session = requests.Session()

        response1 = session.post('https://api.qiwi.com/oauth/authorize', cookies=_gen_reg_platform()[0],
                                 headers=_gen_reg_platform()[1], data=data)

        if response1.ok:
            token_id = str(response1.json().get('token_id'))
            cookies = {
                'user_info': '1',
                'uxs_mig': '1',
                'uxs_uid': 'ed927e60-0d7c-11ed-92cb-578b411d6d00',
                'token-tail-checkout-oauth': '71a61735e8397729',
                'spa_upstream': 'af0376ede1e7ba4eed661170519eedd4',
                'test.for.third.party.cookie': 'yes',
                'node': 'd422e0fa2b1fc4986003233b7d4e37e7',
                'token-tail': '912144989576f070',
                'JSESSIONID': 'C14A7E7A3CB5B682B3E793D02D89E28A.node-s3253',
                'ref': 'newsite_index_1',
                'auth_ukafokfuabbuzdckyiwlunsh': 'MDA1fF98X3wGNVJ4MVgPYGNYDwcAG0AREFRVQFALUE4KKHc1FnQWew4YcGhoB2Z'
                                                 '/CXRaZVJ'
                                                 '+aEpqPVhxKhANFEkXFEdlWgBjA2MadmBUWH5'
                                                 '8VFwDUgJDREMAGh0YX1dWV3pxZkR3SA==',
            }

            headers = {
                'authority': 'api.qiwi.com',
                'accept': 'application/json',
                'accept-language': 'ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7',
                'dnt': '1',
                'origin': 'https://api.qiwi.com',
                'referer': 'https://api.qiwi.com/register/form.action?ref=newsite_index_1',
                'sec-ch-ua': '".Not/A)Brand";v="99", "Google Chrome";v="103", "Chromium";v="103"',
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': '"Windows"',
                'sec-fetch-dest': 'empty',
                'sec-fetch-mode': 'cors',
                'sec-fetch-site': 'same-origin',
                'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
                              'Chrome/103.0.0.0 Safari/537.36',
            }

            data = {
                'client_id': 'sso.qiwi.com',
                'response_type': 'code',
                'username': f'+{str(phone)}',
                'password': password,
                'token_id': token_id,
            }

            response = session.post('https://api.qiwi.com/oauth/authorize', cookies=cookies, headers=headers, data=data)

            if response.ok:
                SaveDict.phone = str(phone)
                SaveDict.password = password

                self.save_account()

                return True

            else:
                return response.content, response.status_code

        else:
            js_: dict = response1.json()
            return f'Ошибка: {js_.get("error_description", "no info")}'
