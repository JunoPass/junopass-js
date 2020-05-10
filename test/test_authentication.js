import nacl from "tweetnacl"
var assert = require('chai').assert;

import junopass from "../index"

nacl.util = require('tweetnacl-util');

describe('setupDevice', function () {
    it('should return a publicKey and secretKey', function () {
        let keys = junopass.setupDevice()
        assert.notEqual(keys.publicKey, null)
        assert.notEqual(keys.secretKey, null)
        assert.notEqual(keys.secretKey, keys.publicKey)
    });
});


describe('authenticate', function () {
    it('should return a challenge and device id', function () {
        junopass.accessToken = "xx"
        junopass.junoPassPublicKey = "xx"
        junopass.projectID = 1

        let keys = junopass.setupDevice()
        let publicKey = keys.publicKey
        let resp = junopass.authenticate("EMAIL", "test@gmail.com", publicKey)

        assert.notEqual(resp, null)
        assert.notEqual(resp.validChallenge, null)
        assert.notEqual(resp.deviceID, null)
    });
});