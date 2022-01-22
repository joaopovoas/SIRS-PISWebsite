
import asyncio
from string import printable
import websockets
import json
import base64
from cryptography.x509 import load_pem_x509_certificate, ocsp
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.serialization import load_der_public_key

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
from OpenSSL.crypto import load_certificate, load_privatekey
from OpenSSL.crypto import X509Store, X509StoreContext
from OpenSSL import crypto


def getTimestamp():
    return int((datetime.utcnow() - datetime(1970, 1, 1)).total_seconds() * 1000)


def createPacket(packetData, encryption, encryptor=None, signer=None):
    currentTimestamp = getTimestamp()
    packet = {}
    packetData["timestamp"] = currentTimestamp
    packet["data"] = packetData

    # Sign packet
    message = json.dumps(packet["data"], separators=(',', ':')).encode('utf-8')
    packet["hash"] =  signer(message, padding.PKCS1v15(), algorithm=hashes.SHA256()).hex()
    

    if encryption == 'RSA':
        packet["data"] = encryptor(message,  padding.OAEP(mgf=padding.MGF1(
            algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    elif encryption == 'AES':
        packet["data"] = encryptor.update(message) + encryptor.finalize()
    elif encryption == 'RAW':
        packet["data"] = message

    packet["data"] = base64.b64encode(packet["data"]).decode()

    packet = bytes(json.dumps(packet, separators=(',', ':')), 'utf-8')

    return currentTimestamp, base64.b64encode(packet).decode("utf-8")


def parsePacket(data, currentTimestamp, encryption, decryptor=None, verifier=None):
    request = base64.b64decode(data)
    request = json.loads(request)

    request["data"] = base64.b64decode(request["data"])

    if encryption == 'RSA':
        request["data"] = decryptor(request["data"],  padding.OAEP(mgf=padding.MGF1(
            algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    elif encryption == 'AES':
        request["data"] = decryptor.update(request["data"]) + decryptor.finalize()

    request["data"] = json.loads(request["data"])

    currentTimestamp = verifyTimestamp(request, currentTimestamp)

    #! Add hashv erification for js client packets (when verifier is none since client does not sign)

    if(verifier):
        verifySignature(request, verifier)

    if not currentTimestamp or not verifyHash(request):
        return -1, request

    return currentTimestamp, request


def signPacket(packet, senderCertificate):
    pkey = ""
    with open("/code/webapp/certs/pis.key", "r") as key_file:
        pkey = RSA.importKey(key_file.read())


    message = json.dumps(packet["data"], separators=(',', ':'))
    h = SHA256.new(message.encode('utf-8'))
    signature = pkcs1_15.new(pkey).sign(h)

    return signature.hex()


def verifyTimestamp(packet, currentTimestamp):
    print(packet["data"]["timestamp"])
    print(currentTimestamp)
    if packet["data"]["timestamp"] <= currentTimestamp:
        print("Invalid timestamp")
        return 0

    return packet["data"]["timestamp"]


def verifySignature(packet, verifier):
    verified = verifier(bytes(bytearray.fromhex(packet["hash"])), json.dumps(packet["data"], separators=(',', ':')).encode(), padding.PKCS1v15(), algorithm=hashes.SHA256())
    # add try catch
    print("Signature verified:" + str(verified == None))

    return verified


def verifyCertificate(pem_data_to_check):

    with open("/code/webapp/certs/myCA.pem", "rb") as key_file:
        root_cert = load_certificate(crypto.FILETYPE_PEM, key_file.read())
        
        untrusted_cert = load_certificate(crypto.FILETYPE_PEM, pem_data_to_check.encode())
        store = X509Store()
        store.add_cert(root_cert)
        store_ctx = X509StoreContext(store, untrusted_cert)
        try:
            store_ctx.verify_certificate()
            print("certificate verified")
            return True
        except crypto.X509StoreContextError as e:
            print("certificate not verified")
   
    return False



def verifyHash(packet):
    m = hashlib.sha256()

    m.update(bytes(json.dumps(packet["data"], separators=(',', ':')), 'utf-8'))
    dataHash = m.hexdigest()

    return dataHash == packet["hash"]
    