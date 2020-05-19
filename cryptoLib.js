const crypto = require("crypto");
const eccrypto = require("eccrypto");


function createAESKey() {
    return crypto.randomBytes(32);    
}


function createECKeys() {
    let privateKey = eccrypto.generatePrivate();
    let publicKey = eccrypto.getPublic(privateKey);

   
    let privKeyStr = '0x' + privateKey.toString('hex');
    let x = publicKey.slice(1, 33);
    let y = publicKey.slice(33, 65);

    return ({
        privateKey: privKeyStr,
        publicKeyX: '0x' + x.toString('hex'),
        publicKeyY: '0x' + y.toString('hex'),
    });
}


function encryptBuffer(data) {
    const iv = crypto.randomBytes(16);
    
    const key = createAESKey();
    
    let cipher = crypto.createCipheriv("aes-256-cbc", key, iv);

    let encrypted = cipher.update(data);
    encrypted = Buffer.concat([encrypted, cipher.final()]);

    return ({
        key: '0x' + key.toString('hex'),
        iv: '0x' + iv.toString('hex'),
        ciphertext: encrypted
    });
}


function decryptBuffer(data, key, iv) {
    keyBuffer = Buffer.from(key.slice(2), 'hex');
    ivBuffer = Buffer.from(iv.slice(2), 'hex');

    let decipher = crypto.createDecipheriv("aes-256-cbc", keyBuffer, ivBuffer);

    let decrypted = decipher.update(data);
    decrypted = Buffer.concat([decrypted, decipher.final()]);


    return decrypted;
}


async function encryptForPublicKey(x, y, data) {
    xStr = x.slice(2);
    yStr = y.slice(2);

    keyStr = '04' + xStr + yStr;
    
    let enc = await eccrypto.encrypt(Buffer.from(keyStr, 'hex'), data);
   
    let dataObj = {
        iv: '0x' + enc.iv.toString('hex'),
        ephemECx: '0x' + enc.ephemPublicKey.slice(1, 33).toString('hex'),
        ephemECy: '0x' + enc.ephemPublicKey.slice(33, 65).toString('hex'),
        ciphertext: '0x' + enc.ciphertext.toString('hex'),
        mac: '0x' + enc.mac.toString('hex')
    };
   
    return dataObj;
}


async function decryptWithPrivateKey(key, dataObject) {
    keyStr = key.slice(2);
    
    ephemPublicKeyStr = '04' + dataObject.ephemECx.slice(2) + dataObject.ephemECy.slice(2);

    data = {
        iv: Buffer.from(dataObject.iv.slice(2), 'hex'),
        ephemPublicKey: Buffer.from(ephemPublicKeyStr, 'hex'),
        ciphertext: Buffer.from(dataObject.ciphertext.slice(2), 'hex'),
        mac: Buffer.from(dataObject.mac.slice(2), 'hex')
    }

    let dec = await eccrypto.decrypt(Buffer.from(keyStr, 'hex'), data);
    return dec;
}


let cryptoLibExports = {
    createAESKey: createAESKey,
    encryptBuffer: encryptBuffer,
    decryptBuffer: decryptBuffer,
    encryptForPublicKey: encryptForPublicKey,
    decryptWithPrivateKey: decryptWithPrivateKey,
    createECKeys: createECKeys,
};
  
module.exports = cryptoLibExports;
