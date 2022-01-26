import os
import asyncio
from string import printable
import websockets
import json
import base64
from cryptography.x509 import load_pem_x509_certificate, ocsp
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from datetime import datetime
import urllib.parse
import hashlib
from argon2 import PasswordHasher
from communication import *
from mail import *

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.types import Integer, Text, String, BigInteger, Float
from sqlalchemy import Column
import uuid

Base = declarative_base()


class Useralchemy(Base):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    email = Column(String(100), unique=True, nullable=False)
    password = Column(String(97), nullable=False)
    cardinfo = Column(String(600), nullable=False)
    infosalt = Column(String(50), nullable=False)
    role = Column(String(50), default="standard", nullable=False)


class Transactionalchemy(Base):
    __tablename__ = 'transaction'
    id = Column(Integer, primary_key=True)
    transactionID = Column(String(97), unique=True, nullable=False)
    price = Column(Float, nullable=False)
    currency = Column(String(97), nullable=False)
    bank = Column(String(97), nullable=False)
    paidbyemail = Column(String(100), default="UNPAID", nullable=False)
    


engine = create_engine(
    'mysql://root:password@' + "172.18.1.4" + '/testpis',
    echo=True)

Base.metadata.create_all(engine)

Session = sessionmaker(bind=engine)
session = Session()


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


async def informMerchant(transactionID):
    currentTimestamp = getTimestamp()
    private_key = ''

    with open("/code/webapp/certs/pis.key", "rb") as key_file:
        private_key = load_pem_private_key(key_file.read(), None)

    websocket = await websockets.connect("ws://172.18.2.3:10500")

    currentTimestamp, request = createPacket(
        {"message": "GET CERTIFICATE"}, 'RAW', signer=private_key.sign)

    await websocket.send(request)

    with open("/code/webapp/certs/pis.crt", "r") as cert:
        currentTimestamp, request = createPacket(
            {"message": cert.read()}, 'RAW', signer=private_key.sign)

    await websocket.send(request)

    response = await websocket.recv()
    currentTimestamp, response = parsePacket(response, currentTimestamp, 'RAW')

    print(response)

    if not verifyCertificate(response["data"]["message"]):
        print("PIS certificate is invalid")
        return

    cert = load_pem_x509_certificate(response["data"]["message"].encode())

    # ---- SecretKey exchange ----

    response = await websocket.recv()
    currentTimestamp, response = parsePacket(
        response, currentTimestamp, 'RSA', decryptor=private_key.decrypt, verifier=cert.public_key().verify)

    print(response)

    aes_key = base64.b64decode(response["data"]["key"])
    aes_iv = base64.b64decode(response["data"]["iv"])

    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(aes_iv))


    data = {"transactionID": transactionID}

    currentTimestamp, response = createPacket(
        data, 'AES', cipher.encryptor(), signer=private_key.sign)

    await websocket.send(response)

    response = await websocket.recv()
    currentTimestamp, response = parsePacket(
        response, currentTimestamp, 'AES', decryptor=cipher.decryptor(), verifier=cert.public_key().verify)

    print(response)




async def createTransaction(price, currency, bankAccount, email, password):
    currentTimestamp = getTimestamp()
    private_key = ''

    with open("/code/webapp/certs/pis.key", "rb") as key_file:
        private_key = load_pem_private_key(key_file.read(), None)

    websocket = await websockets.connect("ws://172.18.3.3:9000")

    currentTimestamp, request = createPacket(
        {"message": "GET CERTIFICATE"}, 'RAW', signer=private_key.sign)

    await websocket.send(request)

    with open("/code/webapp/certs/pis.crt", "r") as cert:
        currentTimestamp, request = createPacket(
            {"message": cert.read()}, 'RAW', signer=private_key.sign)

    await websocket.send(request)

    response = await websocket.recv()
    currentTimestamp, response = parsePacket(response, currentTimestamp, 'RAW')

    print(response)

    if not verifyCertificate(response["data"]["message"]):
        print("PIS certificate is invalid")
        return

    cert = load_pem_x509_certificate(response["data"]["message"].encode())

    # ---- SecretKey exchange ----

    response = await websocket.recv()
    currentTimestamp, response = parsePacket(
        response, currentTimestamp, 'RSA', decryptor=private_key.decrypt, verifier=cert.public_key().verify)

    print(response)

    aes_key = base64.b64decode(response["data"]["key"])
    aes_iv = base64.b64decode(response["data"]["iv"])

    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(aes_iv))

    card_info = getUserCardInfo(email, password)

    data = {"currency": currency, "price": price,
            "bankAccount": bankAccount, "email": email, "card_info": card_info}

    currentTimestamp, response = createPacket(
        data, 'AES', cipher.encryptor(), signer=private_key.sign)

    await websocket.send(response)

    response = await websocket.recv()
    currentTimestamp, response = parsePacket(
        response, currentTimestamp, 'AES', decryptor=cipher.decryptor(), verifier=cert.public_key().verify)

    print(response)


def verify_login(email, password):
    user = session.query(Useralchemy).filter_by(email=email).first()
    ph = PasswordHasher()

    if not user:
        return False

    try:
        ph.verify(user.password, password)
        return True
    except:
        return False


def verify_transaction(transactionID):
    user = session.query(Transactionalchemy).filter_by(
        transactionID=transactionID).first()
    if not user:
        return False
    return True


async def merchantHandler(websocket):
    currentTimestamp = getTimestamp() - 100
    private_key = ''
    with open("/code/webapp/certs/pis.key", "rb") as key_file:
        private_key = load_pem_private_key(key_file.read(), None)

    # ---- PisCertificate ----

    request = await websocket.recv()
    currentTimestamp, request = parsePacket(request, currentTimestamp, 'RAW')
    print(request)

    if request["data"]["message"] == "GET CERTIFICATE":
        with open("/code/webapp/certs/pis.crt", "r") as cert:
            # cert = load_pem_x509_certificate(bytes(cert, 'utf-8'))
            currentTimestamp, response = createPacket(
                {"message": cert.read()}, 'RAW', signer=private_key.sign)
            await websocket.send(response)
    else:
        print("Invalid request syntax")
        return

    # ---- MerchantCertificate ----

    response = await websocket.recv()
    currentTimestamp, response = parsePacket(response, currentTimestamp, 'RAW')

    print(response)

    if not verifyCertificate(response["data"]["message"]):
        print("PIS certificate is invalid")
        return

    cert = load_pem_x509_certificate(
        bytes(response["data"]["message"], 'utf-8'))

    # ---- SecretKey exchange ----

    aes_key = os.urandom(32)
    aes_iv = os.urandom(16)

    data = {"key": base64.b64encode(aes_key).decode(
    ), "iv": base64.b64encode(aes_iv).decode()}

    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(aes_iv))
    encryptor = cipher.encryptor()

    currentTimestamp, response = createPacket(
        data, 'RSA', encryptor=cert.public_key().encrypt, signer=private_key.sign)

    await websocket.send(response)

    # ----- Create transaction ----

    request = await websocket.recv()
    currentTimestamp, request = parsePacket(
        request, currentTimestamp, 'AES', cipher.decryptor(), verifier=cert.public_key().verify)
    print(request)

    transactionID = str(uuid.uuid4())
    token = Transactionalchemy(transactionID=transactionID,
                        bank="324728374832",
                        price=request["data"]["price"],
                        currency=request["data"]["currency"])
    session.add(token)
    session.commit()

    response = {"transactionID": transactionID}
    currentTimestamp, response = createPacket(
        response, 'AES', encryptor=cipher.encryptor(), signer=private_key.sign)

    await websocket.send(response)


async def clientHandler(websocket):
    currentTimestamp = getTimestamp() - 100
    private_key = ''
    with open("/code/webapp/certs/pis.key", "rb") as key_file:
        private_key = load_pem_private_key(key_file.read(), None)

    # ---- PisCertificate ----

    request = await websocket.recv()
    currentTimestamp, request = parsePacket(request, currentTimestamp, 'RAW')
    print(request)

    if request["data"]["message"] == "GET CERTIFICATE":
        with open("/code/webapp/certs/pis.crt", "r") as cert:
            # cert = load_pem_x509_certificate(bytes(cert, 'utf-8'))
            currentTimestamp, response = createPacket(
                {"message": cert.read()}, 'RAW', signer=private_key.sign)
            await websocket.send(response)
    else:
        print("Invalid request syntax")
        return

    # ---- SecretKey exchange ----

    request = await websocket.recv()
    currentTimestamp, request = parsePacket(
        request, currentTimestamp, 'RSA', private_key.decrypt)
    print(request)

    aes_key = base64.b64decode(request["data"]["key"])
    aes_iv = base64.b64decode(request["data"]["iv"])
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(aes_iv))
    encryptor = cipher.encryptor()

    response = {"message": "OK"}
    currentTimestamp, response = createPacket(
        response, 'AES', cipher.encryptor(), signer=private_key.sign)

    await websocket.send(response)

    # ----- LOGIN and start transaction ----

    request = await websocket.recv()
    currentTimestamp, request = parsePacket(
        request, currentTimestamp, 'AES', cipher.decryptor())
    print(request)

    reponse = {}

    if not verify_transaction(request["data"]["transactionID"]):
        response = {"message": "INVALID TRANSACTION ID"}
    elif not verify_login(request["data"]["email"], request["data"]["password"]):
        response = {"message": "BAD CREDENTIALS"}
    else:
        response = {"message": "ACCEPTED"}

    currentTimestamp, response = createPacket(
        response, 'AES', cipher.encryptor(), signer=private_key.sign)

    await websocket.send(response)

    # --------- 2FA ----

    import random
    import string

    letters = string.digits
    token2FA = ''.join(random.choice(letters) for i in range(5))

    send_verification(request["data"]["email"], token2FA)

    print(request["data"]["email"] + str(token2FA))

    expiration = getTimestamp() + 5*60*1000

    request2fa = await websocket.recv()
    currentTimestamp, request2fa = parsePacket(
        request2fa, currentTimestamp, 'AES', cipher.decryptor())
    print(request2fa)

    transaction = session.query(Transactionalchemy).filter_by(
        transactionID=request["data"]["transactionID"]).first()

    if(request2fa["data"]["2FAToken"] != token2FA):
        response = {"message": "WRONG 2FA TOKEN"}
    elif expiration < getTimestamp():
        response = {"message": "2FA TOKEN EXPIRED"}
    else:
        await createTransaction(transaction.price,
                          transaction.currency,
                          transaction.bank,
                          request["data"]["email"],
                          request["data"]["password"])

        response = {"message": "PAID"}

        await informMerchant(request["data"]["transactionID"])

    currentTimestamp, response = createPacket(
        response, 'AES', cipher.encryptor(), signer=private_key.sign)

    await websocket.send(response)


start_server = websockets.serve(merchantHandler, "0.0.0.0", 8755)

asyncio.get_event_loop().run_until_complete(start_server)

start_server = websockets.serve(clientHandler, "0.0.0.0", 8765)

asyncio.get_event_loop().run_until_complete(start_server)

asyncio.get_event_loop().run_forever()
