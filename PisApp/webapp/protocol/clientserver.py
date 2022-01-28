import asyncio
import websockets
import json
import base64
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import load_pem_private_key
import hashlib
from argon2 import PasswordHasher
from communication import *
from mail import *
import random
import string
from sqlalchemymodels import *

session = getAlchemySession()


def getUserCardInfo(email, password):
    user = session.query(Useralchemy).filter_by(email=email).first()

    key_hash = hashlib.sha256()
    key_hash.update(bytes(password + user.infosalt[:25], 'utf8'))
    key_hash = key_hash.digest()

    iv_hash = hashlib.sha256()
    iv_hash.update(bytes(password + user.infosalt[25:], 'utf8'))
    iv_hash = hashlib.md5(iv_hash.digest()).digest()

    cipher = Cipher(algorithms.AES(key_hash), modes.CFB(iv_hash))

    decryptor = cipher.decryptor()
    unencrypted_card_info = decryptor.update(base64.b64decode(user.cardinfo)) + decryptor.finalize()

    return json.loads(unencrypted_card_info)


def verify_login(email, password):
    user = session.query(Useralchemy).filter_by(email=email).first()
    ph = PasswordHasher()

    if not user:
        return False
    try:
        ph.verify(user.password, password)
    except:
        return False

    return True


def verify_transaction(transactionID):
    transaction = session.query(Transactionalchemy).filter_by(
        transactionID=transactionID).first()

    print(transaction)

    if transaction.paidbyemail != "UNPAID":
        return False

    if not transaction:
        return False
    return True


async def informMerchant(transactionID):
    currentTimestamp = getTimestamp() - 5000
    private_key = ''

    with open("/code/webapp/certs/pis.key", "rb") as key_file:
        private_key = load_pem_private_key(key_file.read(), None)

    websocket = await websockets.connect("ws://172.18.2.3:10500")

    # ---- Certificate exchange ----

    request = await sendPacket(
        websocket, {"message": "GET CERTIFICATE"}, 'RAW')

    with open("/code/webapp/certs/pis.crt", "r") as cert:
        request = await sendPacket(
            websocket, {"message": cert.read()}, 'RAW')

    currentTimestamp, response = await getPacket(
        websocket, currentTimestamp, 'RAW')

    if not verifyCertificate(response["data"]["message"], "/code/webapp/certs/myCA.pem"):
        print("Merchant certificate is invalid")
        return

    cert = load_pem_x509_certificate(response["data"]["message"].encode())

    # ---- SecretKey exchange ----

    currentTimestamp, response = await getPacket(
        websocket, currentTimestamp, 'RSA', decryptor=private_key.decrypt, verifier=cert.public_key().verify)

    aes_key = base64.b64decode(response["data"]["key"])
    aes_iv = base64.b64decode(response["data"]["iv"])

    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(aes_iv))

    # ---- Inform Merchant of paid transaction ----

    data = {"transactionID": transactionID}

    response = await sendPacket(
        websocket, data, 'AES', cipher.encryptor(), signer=private_key.sign)

    # ---- OK ----

    currentTimestamp, response = await getPacket(
        websocket, currentTimestamp, 'AES', decryptor=cipher.decryptor(), verifier=cert.public_key().verify)


async def bankMock(price, currency, bankAccount, email, password):
    currentTimestamp = getTimestamp() - 5000
    private_key = ''

    with open("/code/webapp/certs/pis.key", "rb") as key_file:
        private_key = load_pem_private_key(key_file.read(), None)

    websocket = await websockets.connect("ws://172.18.3.3:9000")

    # ---- Certificate exchange ----

    request = await sendPacket(
        websocket, {"message": "GET CERTIFICATE"}, 'RAW')

    with open("/code/webapp/certs/pis.crt", "r") as cert:
        request = await sendPacket(
            websocket, {"message": cert.read()}, 'RAW')

    currentTimestamp, response = await getPacket(
        websocket, currentTimestamp, 'RAW')

    if not verifyCertificate(response["data"]["message"], "/code/webapp/certs/myCA.pem"):
        print("Bank certificate is invalid")
        return

    cert = load_pem_x509_certificate(response["data"]["message"].encode())

    # ---- SecretKey exchange ----

    currentTimestamp, response = await getPacket(
        websocket, currentTimestamp, 'RSA', decryptor=private_key.decrypt, verifier=cert.public_key().verify)

    aes_key = base64.b64decode(response["data"]["key"])
    aes_iv = base64.b64decode(response["data"]["iv"])

    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(aes_iv))

    # ---- Send user credit cart info to dummy bank ----

    card_info = getUserCardInfo(email, password)

    data = {"currency": currency, "price": price,
            "bankAccount": bankAccount, "email": email, "card_info": card_info}

    response = await sendPacket(
        websocket, data, 'AES', cipher.encryptor(), signer=private_key.sign)

    # ---- Ok ----

    currentTimestamp, response = await getPacket(
        websocket, currentTimestamp, 'AES', decryptor=cipher.decryptor(), verifier=cert.public_key().verify)


async def clientHandler(websocket):
    currentTimestamp = getTimestamp() - 5000
    private_key = ''
    with open("/code/webapp/certs/pis.key", "rb") as key_file:
        private_key = load_pem_private_key(key_file.read(), None)

    # ---- PisCertificate ----

    currentTimestamp, request = await getPacket(websocket, currentTimestamp, 'RAW')

    if request["data"]["message"] == "GET CERTIFICATE":
        with open("/code/webapp/certs/pis.crt", "r") as cert:
            response = await sendPacket(
                websocket, {"message": cert.read()}, 'RAW')
    else:
        print("Invalid request syntax")
        return

    # ---- SecretKey exchange ----
    currentTimestamp, request = await getPacket(
        websocket, currentTimestamp, 'RSA', private_key.decrypt)


    aes_key = base64.b64decode(request["data"]["key"])
    aes_iv = base64.b64decode(request["data"]["iv"])
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(aes_iv))

    response = {"message": "OK"}
    response = await sendPacket(
        websocket, response, 'AES', cipher.encryptor(), signer=private_key.sign)

    # ----- LOGIN and start transaction ----

    currentTimestamp, request = await getPacket(
        websocket, currentTimestamp, 'AES', cipher.decryptor())

    reponse = {}

    if not verify_transaction(request["data"]["transactionID"]):
        response = {"message": "INVALID TRANSACTION ID"}
    elif not verify_login(request["data"]["email"], request["data"]["password"]):
        response = {"message": "BAD CREDENTIALS"}
    else:
        response = {"message": "ACCEPTED"}

    response = await sendPacket(
        websocket, response, 'AES', cipher.encryptor(), signer=private_key.sign)

    # --------- 2FA ----

    letters = string.digits
    token2FA = ''.join(random.choice(letters) for i in range(5))

    send_verification(request["data"]["email"], token2FA)

    # A token is valid for 5 minutes
    expiration = getTimestamp() + 5*60*1000

    currentTimestamp, request2fa = await getPacket(
        websocket, currentTimestamp, 'AES', cipher.decryptor())


    transaction = session.query(Transactionalchemy).filter_by(
        transactionID=request["data"]["transactionID"]).first()


    if(request2fa["data"]["2FAToken"] != token2FA):
        response = {"message": "WRONG 2FA TOKEN"}
    elif expiration < getTimestamp():
        response = {"message": "2FA TOKEN EXPIRED"}
    else:
        await bankMock(transaction.price,
                       transaction.currency,
                       transaction.bank,
                       request["data"]["email"],
                       request["data"]["password"])

        response = {"message": "PAID"}

        transaction.paidbyemail = request["data"]["email"]
        session.commit()

        await informMerchant(request["data"]["transactionID"])

    response = await sendPacket(
        websocket, response, 'AES', cipher.encryptor(), signer=private_key.sign)



start_server = websockets.serve(clientHandler, "0.0.0.0", 8765)

print("[+] Client server running")

asyncio.get_event_loop().run_until_complete(start_server)

asyncio.get_event_loop().run_forever()
