/**
 * Generate device public and private key pairs
 */
export default function generateDeviceKeys() {
  return {
    publicKey: "",
    privateKey: ""
  }
}

/**
 * Sign message with your own key i.e device private key
 * @param {*} private_key_hex 
 * @param {*} message 
 */
export default function signMessage(private_key_hex, message) {
  return "hash"
}

/**
 * Verify the authenticity of JunoPass message using its public key.
 * Return a boolean as per its status
 * @param {*} publicKey 
 * @param {*} signedMessage 
 */
export default function verifyJunoPassMessage(publicKey, signedMessage) {
  return "decoded message"
}