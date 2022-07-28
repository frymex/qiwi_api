from api import Qiwi

qiwi = Qiwi('username', 'password', )  # auth
qiwi.set_rucaptcha('rucaptcha key')  # key from rucapatcha


def create_new_qiwi_account():
    phone = input('PHONE NUMBER WITHOUT + ')
    x = qiwi.create_account('')
    code = input('Code: ')
    password = input('Password: ')

    creating = qiwi.submit_qiwi_reg(code, confirmation_id=x, phone=phone, password=password)

    if creating:
        print('Qiwi successful created')
    else:
        exit(creating[0])

    # after creating you can use global methods to use with qiwi


def get_full_info():
    # this method returns full info of your qiwi on json format

    balance = qiwi.get_balance().as_json()
    nickname = qiwi.get_nickname().as_json()

    identifications = qiwi.get_identifications().identifications

    results = [balance, nickname, [x for x in identifications]]
    print(results)


def create_p2p_keys():
    x = qiwi.create_p2p_keys('HERE INPUT KEYS NAME')
    print('PAIR NAME:', x.pair_name, 'Public key:', x.publicKey, 'Secret key:', x.secretKey)
    qiwi.block_p2p_key(x.publicKey) # delete pair

create_p2p_keys()
