var assert = require('chai').assert;
import nacl from "tweetnacl"

nacl.util = require('tweetnacl-util');

import signatures from "./../src/signatures"


describe('generateDeviceKeys', function () {
  it('should return a publicKey and secretKey', function () {
    let keys = signatures.generateDeviceKeys()
    assert.notEqual(keys.publicKey, null)
    assert.notEqual(keys.secretKey, null)
    assert.notEqual(keys.secretKey, keys.publicKey)
  });
});

describe('signedMessage', function () {
  it('should return a signed message. Not expected to be null', function () {
    let keys = signatures.generateDeviceKeys()
    assert.notEqual(keys.publicKey, null)
    assert.notEqual(keys.secretKey, null)
    assert.notEqual(keys.secretKey, keys.publicKey)

    let secretKey = nacl.util.decodeBase64(keys.secretKey)
    console.log("secretKey length", secretKey)
    let message = nacl.util.decodeUTF8("hello world")
    let signedMessage = signatures.signedMessage(secretKey, message)
    assert.notEqual(signedMessage, null)
  });
});

describe('verifyMessage', function () {
  it('sent message should match verified message', function () {
    let keys = signatures.generateDeviceKeys()
    assert.notEqual(keys.publicKey, null)
    assert.notEqual(keys.secretKey, null)
    assert.notEqual(keys.secretKey, keys.publicKey)

    let secretKey = nacl.util.decodeBase64(keys.secretKey)
    console.log("secretKey length", secretKey)
    let message = nacl.util.decodeUTF8("hello world")
    let signedMessage = signatures.signedMessage(secretKey, message)
    assert.notEqual(signedMessage, null)

    // Verify
    let publicKey = nacl.util.decodeBase64(keys.publicKey)
    let verified = signatures.verifyJunoPassMessage(publicKey, signedMessage)
    console.log("Verified Message:", nacl.util.encodeUTF8(verified))
    assert.notEqual(verified, null)
    assert.deepEqual(verified, message)
  });
});