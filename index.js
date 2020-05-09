import {
    generateDeviceKeys,
    signMessage
} from "./src/signatures"

export default function JunoPass() {
    return {
        /**
         * Generates device signing key
         * Use this only on new devices e.g during setup/registration.
         * Consider keeping the keys in a safe place for future use.
         * Note the private_key must never be shared.
         */
        setupDevice(method, identifier, public_key) {
            return generateDeviceKeys()
        },
        /**
         * Submit authentication details to JunoPass. Verify signed challenge hash for authenticity.
         * @param {*} method 
         * @param {*} identifier 
         * @param {*} public_key 
         */
        authenticate(method, identifier, public_key) {
            return {
                validChallenge: "",
                deviceID: "",
                isLoginRequest: false
            }
        },
        /**
         * Verify OTP message. Send back the user OTP plus a valid challenge obtained in step 1 i.e authenticate function.
         * @param {*} challenge 
         * @param {*} device_id 
         * @param {*} private_key_hex 
         * @param {*} otp 
         */
        verify(challenge, device_id, private_key_hex, otp) {
            let message_hash = signMessage()
            let response = {}
            return response
        }
    }
}