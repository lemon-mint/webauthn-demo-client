
let cid = "";

const new_credential = (sitemane, uname, udname, challenge, id) => {
    let copt = {
        publicKey: {
            rp: {
                name: sitemane,
                id: window.location.host.split(":")[0]
            },
            challenge: hex2arr(challenge),
            user: {
                id: hex2arr(id),
                name: uname,
                displayName: udname
            },
            pubKeyCredParams: [{
                type: "public-key",
                alg: -7
            }],
            timeout: 60000,
            attestation: "none",
            extensions: {
                uvm: true,
                exts: true
            },
            authenticatorSelection: {
                //authenticatorAttachment: "cross-platform",
                userVerification: "preferred",
                requireResidentKey: false
            },
            excludeCredentials: []
        }
    }
    return navigator.credentials.create(copt)
}

const usekey = async (challenge, id) => {
    //console.log(hex2arr(challenge));
    const assertion = await navigator.credentials.get(
        {
            publicKey: {
                challenge: hex2arr(challenge),
                userVerification: "preferred",
                allowCredentials: [
                    {
                        id: hex2arr(id),
                        type: "public-key",
                        transports: ["usb", "nfc", "internal", "ble"]
                    }
                ],
                timeout: 60000
            }
        }
    );
    //console.log("hash:", arr2hex(await crypto.subtle.digest("SHA-256", hex2arr(challenge))));
    //response.authenticatorData
    console.log("authenticatorData:", arr2hex(assertion.response.authenticatorData));
    //response.clientDataJSON
    console.log("clientDataJSON:", arr2hex(assertion.response.clientDataJSON));
    console.log("sig:", arr2hex(assertion.response.signature));
    const tmp = async function () {

        const data = JSON.stringify({
            "authData": arr2hex(assertion.response.authenticatorData),
            "Clientjson": arr2hex(assertion.response.clientDataJSON),
            "signature": arr2hex(assertion.response.signature)
        });
        let req = new XMLHttpRequest();
        req.open("POST", RPserver_Verify);
        req.setRequestHeader("Content-type", "application/json;charset=UTF-8");

        req.setRequestHeader("authData", arr2hex(assertion.response.authenticatorData));
        req.setRequestHeader("Clientjson", arr2hex(assertion.response.clientDataJSON));
        req.setRequestHeader("signature", arr2hex(assertion.response.signature));
        
        req.send(data);
        req.onreadystatechange = (e) => {
            if (req.readyState == 4) {
                console.log(data);
            }
        };
    };
    tmp();

    return assertion
}



function newkey(attestationResponse) {
    var attestationObject = CBOR.decode(attestationResponse.attestationObject);
    //console.log(attestationResponse);
    //console.log(JSON.parse(String.fromCharCode.apply(null, new Uint8Array(attestationResponse.clientDataJSON))));
    //console.log(attestationObject);
    var authData = attestationObject.authData
    const dataView = new DataView(new ArrayBuffer(2));
    const idLenBytes = authData.slice(53, 55);
    idLenBytes.forEach((value, index) => dataView.setUint8(index, value));
    const credentialIdLength = dataView.getUint16();
    const credentialId = authData.slice(55, 55 + credentialIdLength);
    const publicKeyBytes = authData.slice(55 + credentialIdLength);
    const publicKeyObject = CBOR.decode(publicKeyBytes.buffer);
    //console.log("byteid:",credentialId);
    console.log("credentialId:", arr2hex(credentialId));
    //console.log(publicKeyObject);
    //console.log(publicKeyObject["-2"]);
    //console.log(publicKeyObject["-3"]);
    console.log("Publickey X:", arr2hex(publicKeyObject["-2"]));
    console.log("Publickey Y:", arr2hex(publicKeyObject["-3"]));
    cid = arr2hex(credentialId);
    return authData
}


function arr2hex(buffer) {
    return Array.prototype.map.call(new Uint8Array(buffer), x => ('00' + x.toString(16)).slice(-2)).join('');
}

function hex2arr(hexString) {
    return new Uint8Array(hexString.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
}

window.addEventListener(
    "load",
    function () {
        let btn_create = document.getElementById("credentials_create");
        let btn_get = document.getElementById("credentials_get");
        let sitename = document.getElementById("sitename");
        let username = document.getElementById("username");
        let displayname = document.getElementById("displayname");
        let challenge = document.getElementById("challenge");
        btn_create.addEventListener(
            "click",
            () => {
                let randbuf = new Uint8Array(16);
                window.crypto.getRandomValues(randbuf)
                let credential = new_credential(sitename.value, username.value, displayname.value, challenge.value, arr2hex(randbuf));
                credential.then(
                    function (newCredentialInfo) {
                        attestationResponse = newCredentialInfo.response;
                        newkey(attestationResponse);
                    }
                )
            }
        );
        btn_get.addEventListener(
            "click",
            () => {
                if (cid != "") {
                    usekey(challenge.value, cid);
                }
            }
        );
    }
);
