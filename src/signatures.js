import nacl from "tweetnacl"
nacl.util = require('tweetnacl-util');

/**
 * Generate device public and private key pairs
 */
function generateDeviceKeys() {
  let keys = nacl.sign.keyPair()
  keys = {
    "publicKey": nacl.util.encodeBase64(keys.publicKey),
    "secretKey": nacl.util.encodeBase64(keys.secretKey)
  }
  return keys
}

/**
 * Sign message with your own key i.e device private key
 * @param {*} private_key_hex 
 * @param {*} message 
 */
function signMessage(secretKey, message) {
  return nacl.sign(message, secretKey)
}

/**
 * Verify the authenticity of JunoPass message using its public key.
 * Return a boolean as per its status
 * @param {*} publicKey 
 * @param {*} signedMessage 
 */
function verifyJunoPassMessage(publicKey, signedMessage) {
  return nacl.sign.open(signedMessage, publicKey)
}

export default {
  generateDeviceKeys: generateDeviceKeys,
  signedMessage: signMessage,
  verifyJunoPassMessage: verifyJunoPassMessage
}