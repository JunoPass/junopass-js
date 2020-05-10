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
        junopass.accessToken = "8c7a60ada2a65933f0a431921b45368a45fe424d"
        junopass.junoPassPublicKey = "ae7b59d370ec4d04011baf2738ef068cb1dde6d22e55d16e6ccc0f6c69307cc4"
        junopass.projectID = "20cbc960-f786-45fa-a3ad-a9659b097a41"

        let keys = junopass.setupDevice()
        let publicKey = keys.publicKey
        junopass.authenticate("EMAIL", "felix.cheruiyot@kenyaapps.net", publicKey).then(function (resp) {
            assert.notEqual(resp, null)
            assert.notEqual(resp.validChallenge, null)
            assert.notEqual(resp.deviceID, null)
        }).catch(function (err) {
            console.error("Error experienced", err)
        })
    });
});