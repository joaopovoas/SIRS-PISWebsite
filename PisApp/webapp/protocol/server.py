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
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from argon2 import PasswordHasher
from communication import *


from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.types import Integer, Text, String
from sqlalchemy import Column

Base = declarative_base()

engine = create_engine(
    'mysql://usr:password@' + os.environ["host"] + '/test',
    echo=True
)
Session = sessionmaker(bind=engine)
session = Session()

class User(Base):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    email = Column(String(100), unique=True, nullable=False)
    password = Column(String(97), nullable=False)
    role = Column(String(50), default = "standard", nullable=False)

async def merchantHandler(websocket):
    currentTimestamp = getTimestamp()- 100
    private_key = ''
    with open("/code/webapp/certs/pis.key", "rb") as key_file:
        private_key = load_pem_private_key(key_file.read(), None)

    # ---- PisCertificate ----

    request = await websocket.recv()
    currentTimestamp, request = parsePacket(request, currentTimestamp, 'RAW')
    print(request)

    if request["data"]["message"] == "GET CERTIFICATE":
        with open("certs/pis.crt", "r") as cert:
            #cert = load_pem_x509_certificate(bytes(cert, 'utf-8'))
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

    cert = load_pem_x509_certificate(bytes(response["data"]["message"], 'utf-8'))

    

    # ---- SecretKey exchange ----

    aes_key = os.urandom(16)
    aes_iv = os.urandom(16)

    data = {"key" : base64.b64encode(aes_key).decode(), "iv" : base64.b64encode(aes_iv).decode()}

    
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(aes_iv))
    encryptor = cipher.encryptor()

    currentTimestamp, response = createPacket(data, 'RSA', encryptor=cert.public_key().encrypt, signer=private_key.sign)

    await websocket.send(response)


    # ----- Create transaction ----

    request = await websocket.recv()
    currentTimestamp, request = parsePacket(
        request, currentTimestamp, 'AES', cipher.decryptor(), verifier=cert.public_key().verify)
    print(request)



    response = {"transactionID": "89423432434"}
    currentTimestamp, response = createPacket(
        response, 'AES', encryptor=cipher.encryptor(), signer=private_key.sign)

    await websocket.send(response)




def verify_login(email, password):
    user = session.query(User).filter_by(email=email).first()
    ph = PasswordHasher()

    if not user:
       return False

    try:
        ph.verify(user.password, password)
        return True
    except:
        return False




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
            #cert = load_pem_x509_certificate(bytes(cert, 'utf-8'))
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

    reponse ={}

    if(verify_login(request["data"]["email"], request["data"]["password"])):
        response = {"message": "ACCEPTED"}
    else :
        response = {"message": "BAD CREDENTIALS"}

    currentTimestamp, response = createPacket(
        response, 'AES', cipher.encryptor(), signer=private_key.sign)

    await websocket.send(response)

    # --------- 2FA ----

    request = await websocket.recv()
    currentTimestamp, request = parsePacket(
        request, currentTimestamp, 'AES', cipher.decryptor())
    print(request)

    response = {"message": "PAID"}
    currentTimestamp, response = createPacket(
        response, 'AES', cipher.encryptor(), signer=private_key.sign)

    await websocket.send(response)


start_server = websockets.serve(merchantHandler, "0.0.0.0", 8755)

asyncio.get_event_loop().run_until_complete(start_server)

start_server = websockets.serve(clientHandler, "0.0.0.0", 8765)

asyncio.get_event_loop().run_until_complete(start_server)

asyncio.get_event_loop().run_forever()
