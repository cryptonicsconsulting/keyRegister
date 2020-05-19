pragma solidity ^0.5.13;

contract KeyRegister {

    //stores a 64-bit public EC key, stored as the x and y coordinates on the curve for efficiency
    struct pubKey{
        bytes32 x;
        bytes32 y;
    }

    //stores a secret key encrypted with ECIES and the
    struct encSecretKey {
        bytes32 mac;
        bytes32 ephemECx;
        bytes32 ephemECy;
        bytes16 iv;
        bytes16 ivAES;
        bytes ciphertext;
        address delegator;
    }

    //the public keys that can be used to encrypt for an account
    //WARNING: It's best to NOT use the account keypair for this, but a new key pair
    mapping (address => pubKey) public pubKeys;

    //uri -> (account -> encrypted key)
    mapping (string => mapping (address => encSecretKey)) public delegations;


    function setPubKey(bytes32 _x, bytes32 _y) external {
        pubKeys[msg.sender].x = _x;
        pubKeys[msg.sender].y = _y;
    }


    function addAccessDelegation(
        address _account,
        bytes32 _macEC,
        bytes32 _ephemECx,
        bytes32 _ephemECy,
        bytes16 _ivEC,
        bytes16 _ivAES,
        bytes calldata _encryptedKey,
        string calldata _uri
    )
        external
    {
        require((pubKeys[_account].x != 0) && (_account != address(0)), "invalid destination account");

        delegations[_uri][_account] = encSecretKey(
            _macEC,
            _ephemECx,
            _ephemECy,
            _ivEC,
            _ivAES,
            _encryptedKey,
            msg.sender
        );
    }

    function revokeAccessDelegation(address _account, string calldata _uri) external {
        require(delegations[_uri][_account].delegator == msg.sender, "only delegator can revoke access");

        delete(delegations[_uri][_account]);
    }

}