const KeyRegister = artifacts.require("KeyRegister");

const assertRevert = require('./utils/assertRevert').assertRevert;
const cl = require('../cryptoLib.js');
const fs = require("fs");

contract('KeyRegister', (accounts) => {


    beforeEach(async function() {
        this.keyReg = await KeyRegister.new();
        
        //get some EC keys
        this.keys = cl.createECKeys();


        //encrypt a file
        this.plain = fs.readFileSync("./LICENSE");
        this.encrypted = cl.encryptBuffer(this.plain);   
    });
  
  
    describe('registration', function() {
        it('register a public key', async function() {
  
            //register pub key
            await this.keyReg.setPubKey(this.keys.publicKeyX, this.keys.publicKeyY);
           
            const pubK = await this.keyReg.pubKeys(accounts[0]);
            assert.equal(this.keys.publicKeyX, pubK.x, "incorrect public key");
            assert.equal(this.keys.publicKeyY, pubK.y, "incorrect public key");

        });
        
    });

    describe('access delegation', function() {
        it('give access', async function() {
            
            //register pub key
            await this.keyReg.setPubKey(this.keys.publicKeyX, this.keys.publicKeyY);
           
            //encrypt AES key with pub key
            let delegationObject = await cl.encryptForPublicKey(this.keys.publicKeyX, this.keys.publicKeyY, Buffer.from(this.encrypted.key.slice(2), 'hex'));
           
            
            
            //send access delegation key object
            await this.keyReg.addAccessDelegation(
                accounts[0],
                delegationObject.mac,
                delegationObject.ephemECx,
                delegationObject.ephemECy,
                delegationObject.iv,
                this.encrypted.iv,
                delegationObject.ciphertext,
                "./LICENSE.enc",
                { from: accounts[1] }
            );
            
            //load delegation key object from contract
            let delegation = await this.keyReg.delegations("./LICENSE.enc", accounts[0]);
            assert.equal(delegationObject.ciphertext, delegation.ciphertext, "incorrect encrypted key in smart contract");

            //decrypt AES key
            let decryptedKey = await cl.decryptWithPrivateKey(this.keys.privateKey, delegation); 
            assert.equal(this.encrypted.key, '0x' + decryptedKey.toString('hex'), "Decrypted AES key does not much original");
            
              

            //decrypt encrypted uri
            let decrypted = cl.decryptBuffer(this.encrypted.ciphertext, '0x' + decryptedKey.toString('hex'), delegation.ivAES);
            assert.equal(decrypted.toString('ascii'), this.plain.toString('ascii'), "decrypted data does not match original source")
            
        });


        it('reject delegations for unregistered accounts', async function() {           
            //register pub key
            await this.keyReg.setPubKey(this.keys.publicKeyX, this.keys.publicKeyY);
           
            //encrypt AES key with pub key
            let delegationObject = await cl.encryptForPublicKey(this.keys.publicKeyX, this.keys.publicKeyY, Buffer.from(this.encrypted.key.slice(2), 'hex'));
           
            //send access delegation key object
            await assertRevert(this.keyReg.addAccessDelegation(
                accounts[2],
                delegationObject.mac,
                delegationObject.ephemECx,
                delegationObject.ephemECy,
                delegationObject.iv,
                this.encrypted.iv,
                delegationObject.ciphertext,
                "./LICENSE.enc",
                { from: accounts[1] }
            ),
            "cannot encrypt for unregisterd account");

        });

    });


    describe('access revocation', function() {
        it('revoke access', async function() {
            
            //register pub key
            await this.keyReg.setPubKey(this.keys.publicKeyX, this.keys.publicKeyY);
           
            //encrypt AES key with pub key
            let delegationObject = await cl.encryptForPublicKey(this.keys.publicKeyX, this.keys.publicKeyY, Buffer.from(this.encrypted.key.slice(2), 'hex'));
            
            //send access delegation key object
            await this.keyReg.addAccessDelegation(
                accounts[0],
                delegationObject.mac,
                delegationObject.ephemECx,
                delegationObject.ephemECy,
                delegationObject.iv,
                this.encrypted.iv,
                delegationObject.ciphertext,
                "./LICENSE.enc",
                { from: accounts[1] }
            );     
            
            //revoke access    
            await this.keyReg.revokeAccessDelegation(accounts[0], "./LICENSE.enc", { from: accounts[1] });

            
           //try to load delegation key object from contract
           let delegation = await this.keyReg.delegations("./LICENSE.enc", accounts[0]);
           assert.isNull(delegation.ciphertext, "encrypted key should have been deleted");
        });

        it('cannot revoke access for other delagatos', async function() {
            
            //register pub key
            await this.keyReg.setPubKey(this.keys.publicKeyX, this.keys.publicKeyY);
           
            //encrypt AES key with pub key
            let delegationObject = await cl.encryptForPublicKey(this.keys.publicKeyX, this.keys.publicKeyY, Buffer.from(this.encrypted.key.slice(2), 'hex'));
            
            //send access delegation key object
            await this.keyReg.addAccessDelegation(
                accounts[0],
                delegationObject.mac,
                delegationObject.ephemECx,
                delegationObject.ephemECy,
                delegationObject.iv,
                this.encrypted.iv,
                delegationObject.ciphertext,
                "./LICENSE.enc",
                { from: accounts[1] }
            );     
            
            //try to revoke access    
            await assertRevert(this.keyReg.revokeAccessDelegation(accounts[0], "./LICENSE.enc", { from: accounts[2] }), "cannot revoke access from this account");

          
        });

       
    });

});
