var rsa = forge.pki.rsa;


var myCA = '-----BEGIN CERTIFICATE-----\n\
MIIDdzCCAl+gAwIBAgIUX1ejTwSqi4n4bM9tQy2W2fh83X4wDQYJKoZIhvcNAQEL\n\
BQAwSzELMAkGA1UEBhMCUFQxEzARBgNVBAgMClNvbWUtU3RhdGUxDTALBgNVBAoM\n\
BG15Q0ExCzAJBgNVBAsMAkNBMQswCQYDVQQDDAJDQTAeFw0yMjAxMTkyMTMxMzJa\n\
Fw0yNzAxMTgyMTMxMzJaMEsxCzAJBgNVBAYTAlBUMRMwEQYDVQQIDApTb21lLVN0\n\
YXRlMQ0wCwYDVQQKDARteUNBMQswCQYDVQQLDAJDQTELMAkGA1UEAwwCQ0EwggEi\n\
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC4h0ENYnWQp53ADNK78Bp5HSNQ\n\
+pgQuuP6kBCecErvmn6qhEAuSXUdvtCEb9ihOa80+mmIxA2jhihduiJqX+HL9ZBX\n\
n7QMUi4agiGPlVbc6tHLSem06ayZjxU7isT1MpuwRANPdzJq7zrbo+ZZ65pmOxrp\n\
2/yB06DFA+Rf3slEgZ+JB4A8QUmJ6wroePw/3M1+X2cUDpzLsA7x5267weTbDj8N\n\
L4XWfBj/xCx8N4Ts1HEFu91fOywf0RJD0n/0LmlPD2fubT/fzw/YS9CPyadJuCa8\n\
JAeSeNjopAA1dOwEUrBg1ldezkqp6KS8narHQjNwWx3RCj+vFmuuvX96U99rAgMB\n\
AAGjUzBRMB0GA1UdDgQWBBRi+nHeOaBRkiVEHWv116jYa+k0FzAfBgNVHSMEGDAW\n\
gBRi+nHeOaBRkiVEHWv116jYa+k0FzAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3\n\
DQEBCwUAA4IBAQAeWyCwYiUxKeH92PMDtoxf/pV+ZcMgT5zkGulg8ZDXxsuV2nSS\n\
0g3N0J1pxXGqiAt5dJ5ldxwlBDD93cTaHCw3R0kWJz9R2fpKjhkxQtjuV7hNoCpz\n\
6KVHqAn8N2xkmdljKWthpVCRPKAOsTrgf0v3FowGEZDkrMhphy0ejuXHz2eFkvlj\n\
aRWMzkccKwCXV95WM4ErYpig2uf1OQziuI8/RA+1/ZiefixeG3+jkcdJCGScbUC4\n\
6r+q12Pn1ILlgI0hGk0J0GjLJcjBsCawnfwBzqXm2x0cSlSGP9IoEDf7u8hsYa21\n\
UZSv7j5LUBt9QpNVSO9L9rpwQbpXzZQyPUaI\n\
-----END CERTIFICATE-----'


var caCert = forge.pki.certificateFromPem(myCA)


var PaymentProtocol = function (socket, paymentInfo) {
    this.currentState = new CertificateAcquisition(this);
    this.socket = socket
    this.paymentInfo = paymentInfo
    this.currentTimestamp = Date.now()

    this.verifyPacket = function (packet) {
        // initialize
        var sig = new KJUR.crypto.Signature({"alg": "SHA256withRSA"});
        // initialize for signature validation
        sig.init(forge.pki.certificateToPem(this.paymentInfo["pisCert"])); // signer's certificate
        // update data
        sig.updateString(JSON.stringify(packet["data"]))
        // verify signature
        var verified = sig.verify(packet["hash"])

        console.log("\t[+] Signature and integrity verified: " + verified)

        if (!verified) {
            return false
        }

        if (packet["data"]["timestamp"] <= this.currentTimestamp) {
            return false
        }

        this.currentTimestamp = packet["data"]["timestamp"]

        return true

    }

    this.change = function (state) {
        this.currentState = state;
    };

    this.AESEncryption = function (data) {
        this.encryptCipher.update(forge.util.createBuffer(data));
        this.encryptCipher.finish();
        let output = this.encryptCipher.output.data

        this.encryptCipher.start({ iv: this.paymentInfo["iv"] });
        return btoa(output);
    }

    this.AESDecryption = function (data) {
        packet = JSON.parse(data)
        packet["data"] = atob(packet["data"])

        this.decryptCipher.update(forge.util.createBuffer(packet["data"]));
        this.decryptCipher.finish();

        packet["data"] = JSON.parse(this.decryptCipher.output.data)
        this.decryptCipher.start({ iv: this.paymentInfo["iv"] });
        return packet;
    }


    this.RSAEncryption = function (data) {
        return btoa(this.paymentInfo["pisCert"].publicKey.encrypt(data, 'RSA-OAEP', {
            md: forge.md.sha256.create(),
            mgf1: {
                md: forge.md.sha256.create(),
            }
        }));
    }

    this.step = function () {

        if(!this.currentState.canStep())
            return

        let packet = {};
        let [packetData, encryption] = this.currentState.step();

        packetData["timestamp"] = Date.now();

        md = forge.md.sha256.create();

        md.update(JSON.stringify(packetData));
        packet["hash"] = md.digest().toHex();


        switch (encryption) {
            case 'RSA':
                packet["data"] = this.RSAEncryption(JSON.stringify(packetData));
                break;
            case 'AES':
                packet["data"] = this.AESEncryption(JSON.stringify(packetData));
                break;
            case 'RAW':
                packet["data"] = btoa(JSON.stringify(packetData));
                break;
            default:
                console.log("Encryption type " + encryption + " is not a valid option")
        }

        packet = JSON.stringify(packet)

        this.socket.send(btoa(packet));
    };

    this.process = function (data) {
        this.currentState.process(atob(data))
    }

    this.start = function () {
        // 16 => AES-128
        this.paymentInfo["key"] = forge.random.getBytesSync(16);
        this.paymentInfo["iv"] = forge.random.getBytesSync(16);

        this.encryptCipher = forge.cipher.createCipher('AES-CFB', this.paymentInfo["key"]);
        this.encryptCipher.start({ iv: this.paymentInfo["iv"] });

        this.decryptCipher = forge.cipher.createDecipher('AES-CFB', this.paymentInfo["key"]);
        this.decryptCipher.start({ iv: this.paymentInfo["iv"] });

        this.step()
    };
}

var CertificateAcquisition = function (protocolInstance) {
    this.step = function () {
        console.log("[+] CertificateAcquisition")

        return [{ "message": 'GET CERTIFICATE' }, 'RAW'];
    }

    this.canStep = function () {
        return true;
    }

    this.process = function (data) {
        //console.log("[+] Certificate: " + data);

        packet = JSON.parse(data)
        packet["data"] = JSON.parse(atob(packet["data"]))


        try {
            protocolInstance.paymentInfo["pisCert"] = forge.pki.certificateFromPem(packet["data"]["message"]);
        } catch (e) {
            console.error('\t[+] Failed to load CA certificate (' + e.message || e + ')')
            return
        }

        if (!protocolInstance.verifyPacket(packet)) {
            return
        }

        try {
            let verified = caCert.verify(protocolInstance.paymentInfo["pisCert"]);
            console.log('\t[+] CA Verification of cert: ' + verified);
        } catch (e) {
            console.error('\t[+] Failed to verify certificate (' + e.message || e + ')')
            return
        }

        protocolInstance.change(new KeyExchange(protocolInstance));
    }
};


var KeyExchange = function (protocolInstance) {


    this.canStep = function () {
        return true;
    }

    this.step = function () {
        console.log("[+] KeyExchange")

        let request = {}
        request["key"] = btoa(protocolInstance.paymentInfo["key"])
        request["iv"] = btoa(protocolInstance.paymentInfo["iv"])

        return [request, 'RSA'];
    }


    this.process = function (data) {
        let packet = protocolInstance.AESDecryption(data)
   

        if (!protocolInstance.verifyPacket(packet)) {
            return
        }

        console.log("\t[+] Key exchange status: " + JSON.stringify(packet["data"]));
        protocolInstance.change(new TransactionExecution(protocolInstance));
    }

};

var TransactionExecution = function (protocolInstance) {
    this.step = function () {
        console.log("[+] TransactionExecution")

        let request = {}
        request["email"] = protocolInstance.paymentInfo["email"]
        request["password"] = protocolInstance.paymentInfo["password"]
        request["transactionID"] = protocolInstance.paymentInfo["transactionID"]

        return [request, 'AES'];
    }

    this.canStep = function () {
        return true;
    }

    this.process = function (data) {

        let packet = protocolInstance.AESDecryption(data)


        if (!protocolInstance.verifyPacket(packet)) {
            return
        }

        console.log("\t[+] Transaction validation: " + JSON.stringify(packet["data"]));
        protocolInstance.change(new TransactionStrongAuth(protocolInstance));
    }

};



var TransactionStrongAuth = function (protocolInstance) {
    this.step = function () {

        console.log("[+] TransactionStrongAuth")

        request = {}
        request["2FAToken"] = protocolInstance.paymentInfo["2FAToken"]
        request["transactionID"] = protocolInstance.paymentInfo["transactionID"]

        return [request, 'AES'];
    }

    this.canStep = function () {
        return protocolInstance.paymentInfo["2FAToken"] !== undefined;
    }

    this.process = function (data) {
        let packet = protocolInstance.AESDecryption(data)
        
        if (!protocolInstance.verifyPacket(packet)) {
            return
        }

        console.log("\t[+] Transaction result : " + JSON.stringify(packet["data"]));
    }
};








function protocol(email, password, transactionID) {
    paymentInfo = { email: email, password: password, transactionID: transactionID }

    var exampleSocket = new WebSocket("ws://172.19.1.3:8765");
    //window.location.href

    var protocol = new PaymentProtocol(exampleSocket, paymentInfo)


    exampleSocket.onopen = function (event) {
        //console.log(event.data)
        protocol.start()
    }

    exampleSocket.onmessage = function (event) {
        protocol.process(event.data)
        protocol.step()
    }

    exampleSocket.onclose = function (event) {
        if (event.wasClean) {
            console.log(`[close] Connection closed cleanly, code=${event.code} reason=${event.reason}`);
        } else {
            // e.g. server process killed or network down
            // event.code is usually 1006 in this case
            console.log('[close] Connection died');
        }
    };
    
    exampleSocket.onerror = function (error) {
        console.log(`[error] ${error.message}`);
    };
    
    return protocol

}



/*exampleSocket.onopen = function (event) {
    var keypair = rsa.generateKeyPair({bits: 2048, e: 0x10001});

    var cert = forge.pki.createCertificate();

    cert.publicKey = keypair.publicKey;


    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date();
    cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);
    cert.sign(keypair.privateKey);


    exampleSocket.send(forge.pki.certificateToPem(cert))
};*/


