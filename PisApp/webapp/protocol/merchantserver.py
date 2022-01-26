import os
import asyncio
import websockets
import base64
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from communication import *
from mail import *
from sqlalchemymodels import *

session = getAlchemySession()



async def merchantHandler(websocket):
    currentTimestamp = getTimestamp() - 500
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

    # ---- MerchantCertificate ----

    currentTimestamp, response = await getPacket(
        websocket, currentTimestamp, 'RAW')

    if not verifyCertificate(response["data"]["message"], "/code/webapp/certs/myCA.pem"):
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

    response = await sendPacket(
        websocket, data, 'RSA', encryptor=cert.public_key().encrypt, signer=private_key.sign)

    # ----- Create transaction ----

    currentTimestamp, request = await getPacket(
        websocket, currentTimestamp, 'AES', cipher.decryptor(), verifier=cert.public_key().verify)


    transactionID = str(uuid.uuid4())

    token = Transactionalchemy(transactionID=transactionID,
                               bank=request["data"]["bankAccount"],
                               price=request["data"]["price"],
                               currency=request["data"]["currency"])
    session.add(token)
    session.commit()

    response = {"transactionID": transactionID}
    response = await sendPacket(
        websocket, response, 'AES', encryptor=cipher.encryptor(), signer=private_key.sign)

 


start_server = websockets.serve(merchantHandler, "0.0.0.0", 8755)

print("[+] Merchant server running")

asyncio.get_event_loop().run_until_complete(start_server)


asyncio.get_event_loop().run_forever()
