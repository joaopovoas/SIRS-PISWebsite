
import websockets
import json
import base64
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from datetime import datetime
import hashlib
from OpenSSL.crypto import load_certificate
from OpenSSL.crypto import X509Store, X509StoreContext
from OpenSSL import crypto


def getTimestamp():
    return int((datetime.utcnow() - datetime(1970, 1, 1)).total_seconds() * 1000)


async def sendPacket(websocket, packetData, encryption, encryptor=None, signer=None):
    currentTimestamp = getTimestamp()
    packet = {}
    packetData["timestamp"] = currentTimestamp
    packet["data"] = packetData

    # Sign packet
    message = json.dumps(packet["data"], separators=(',', ':')).encode('utf-8')

    if signer:
        packet["hash"] = signer(message, padding.PKCS1v15(), algorithm=hashes.SHA256()).hex()
    else:
        packet["hash"] = calculateHash(message)
    

    if encryption == 'RSA':
        packet["data"] = encryptor(message,  padding.OAEP(mgf=padding.MGF1(
            algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    elif encryption == 'AES':
        packet["data"] = encryptor.update(message) + encryptor.finalize()
    elif encryption == 'RAW':
        packet["data"] = message

    packet["data"] = base64.b64encode(packet["data"]).decode()

    packet = bytes(json.dumps(packet, separators=(',', ':')), 'utf-8')

    encodedPacket = base64.b64encode(packet).decode("utf-8")

    await websocket.send(encodedPacket)

    return encodedPacket


async def getPacket(websocket, currentTimestamp, encryption, decryptor=None, verifier=None):
    data = await websocket.recv()
    
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
        if not verifySignature(request, verifier):
            raise Exception("Signed hash is invalid")
    else:
        if not verifyHash(request):
            raise Exception("Hash is invalid")

    if currentTimestamp == -1:
        raise Exception("Timestamp is invalid")

    print(request["data"])

    return currentTimestamp, request


def verifyTimestamp(packet, currentTimestamp):
    print(packet["data"]["timestamp"])
    print(currentTimestamp)
    if packet["data"]["timestamp"] < currentTimestamp:
        print("Invalid timestamp")
        return -1

    return packet["data"]["timestamp"]


def verifySignature(packet, verifier):
    verified = verifier(bytes(bytearray.fromhex(packet["hash"])), json.dumps(packet["data"], separators=(',', ':')).encode(), padding.PKCS1v15(), algorithm=hashes.SHA256())
    # add try catch
    print("Signature verified:" + str(verified == None))

    return verified == None

def verifyCertificate(pem_data_to_check, ca_certificate_location):

    with open(ca_certificate_location, "rb") as key_file:
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

def calculateHash(message):
    m = hashlib.sha256()
    m.update(message)
    dataHash = m.hexdigest()

    return dataHash
    