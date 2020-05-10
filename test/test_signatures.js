import nacl from "tweetnacl"
var assert = require('chai').assert;

import signatures from "./../src/signatures"

nacl.util = require('tweetnacl-util');

describe('generateDeviceKeys', function () {
  it('should return a publicKey and secretKey', function () {
    let keys = signatures.generateDeviceKeys()
    assert.notEqual(keys.publicKey, null)
    assert.notEqual(keys.secretKey, null)
    assert.notEqual(keys.secretKey, keys.publicKey)
  });
});

describe('signMessage', function () {
  it('should return a signed message', function () {
    let keys = signatures.generateDeviceKeys()
    assert.notEqual(keys.publicKey, null)
    assert.notEqual(keys.secretKey, null)
    assert.notEqual(keys.secretKey, keys.publicKey)

    let secretKey = nacl.util.decodeBase64(keys.secretKey)
    let message = nacl.util.decodeUTF8("hello world")
    let signedMessage = signatures.signMessage(secretKey, message)
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
    let messageStr = "hello world"
    let message = nacl.util.decodeUTF8(messageStr)
    let signedMessage = signatures.signMessage(secretKey, message)
    assert.notEqual(signedMessage, null)

    // Verify
    let publicKey = nacl.util.decodeBase64(keys.publicKey)
    let verified = signatures.verifyJunoPassMessage(publicKey, signedMessage)
    let verifiedStr = nacl.util.encodeUTF8(verified)
    assert.notEqual(verified, null)
    assert.deepEqual(verified, message)
    assert.deepEqual(verifiedStr, messageStr)
  });
});