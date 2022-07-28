import json


class Balance_1:
    def __init__(self, obj: dict):
        self.amount: float = float(obj.get('amount'))
        self.currency: int = int(obj.get('currency'))

    def as_json(self) -> dict:
        return self.__dict__


class Accounts:
    def __init__(self, obj: dict):
        account: dict = obj.get('accounts')[0]
        self.alias: str = account.get('alias')
        self.fsAlias: str = account.get('fsAlias')
        self.bankAlias: str = account.get('bankAlias')
        self.title: str = account.get('title')
        self.hasBalance: bool = account.get('hasBalance')
        self.balance: object = Balance_1(account.get('balance'))

    def as_json(self) -> dict:
        return self.__dict__


class Identification:
    def __init__(self, obj: dict):
        self.firstName = obj.get('firstName')
        self.middleName = obj.get('middleName', None)
        self.lastName = obj.get('lastName')
        self.bankAlias = obj.get('bankAlias')
        self.level = obj.get('level')
        self.birthDate_str = obj.get('birthDate')
        self.passport = obj.get('passport', None)
        self.inn = obj.get('inn', None)
        self.snils = obj.get('snils', None)
        self.oms = obj.get('oms', None)
        self.registrationAddress = obj.get('registrationAddress', None)
        self.passportExpired = obj.get('passportExpired', None)

    def as_json(self) -> dict:
        return self.__dict__


class Identifications:
    def __init__(self, obj: list):
        result = []
        for x in obj:
            result.append(Identification(x))
        self.identifications = result

    def as_json(self) -> dict:
        return self.__dict__


class Access:
    def __init__(self, obj: dict):
        self.SMS_CONFIRM: bool = obj.get('SMS_CONFIRM', None)
        self.TERMINAL_SMS_CONFIRM: bool = obj.get('TERMINAL_SMS_CONFIRM', None)
        self.TERMINAL_PIN_ENTER: bool = obj.get('TERMINAL_PIN_ENTER', None)
        self.SMS_PAY: bool = obj.get('SMS_PAY', None)
        self.ALLOW_CLIENTS: bool = obj.get('ALLOW_CLIENTS', None)

    def as_json(self) -> dict:
        return self.__dict__


class NewPairP2p:
    def __init__(self, obj: dict):
        result: dict = obj.get('result')
        self.pair_name = result.get('name')
        self.publicKey = result.get('publicKey')
        self.secretKey = result.get('secretKey')
        self.createdDateTime = result.get('createdDateTime')

    def as_json(self) -> dict:
        return self.__dict__


class MyP2P_Key:
    def __init__(self, obj: dict):
        self.publicKeyCreatedDate: str = str(obj.get('publicKeyCreatedDtime'))
        self.publicKeyName = obj.get('publicKeyName')
        self.publicKeyStatus = obj.get('publicKeyStatus')
        self.publicKeyValue = obj.get('publicKeyValue')
        self.serverNotificationsUrl = obj.get('serverNotificationsUrl', None)

    def as_json(self) -> dict:
        return self.__dict__


class MyP2P_Keys:
    def __init__(self, obj: dict):
        result = []
        for x in obj.get('result'):
            result.append(MyP2P_Key(x))

    def as_json(self) -> dict:
        return self.__dict__


class Nickname:
    def __init__(self, obj: dict):
        self.canChange: bool = obj.get('canChange')
        self.canUse: bool = obj.get('canUse')
        self.description: str = obj.get('description')
        self.nickname: [str, None] = obj.get('nickname', None)

    def as_json(self) -> dict:
        return self.__dict__
