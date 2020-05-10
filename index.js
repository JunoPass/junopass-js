import nacl from "tweetnacl"
nacl.util = require('tweetnacl-util');


import signatures from "./src/signatures"
import client from "./src/client"

export default {
    /**
     * projectID from JunoPass
     */
    projectID: "",
    /**
     * accessToken from JunoPass
     */
    accessToken: "",
    /**
     * junoPassPublicKey from JunoPass
     */
    junoPassPublicKey: "",
    /**
     * Generates device signing key
     * Use this only on new devices e.g during setup/registration.
     * Consider keeping the keys in a safe place for future use.
     * Note the private_key must never be shared.
     */
    setupDevice(method, identifier, public_key) {
        return signatures.generateDeviceKeys()
    },
    /**
     * Submit authentication details to JunoPass. Verify signed challenge hash for authenticity.
     * @param {*} method 
     * @param {*} identifier 
     * @param {*} publicKey 
     * 
     * @example:
     * junopass.accessToken = "xxx"
     * junopass.junoPassPublicKey = "ae7b59d370ec4d04011baf2738ef068cb1dde6d22e55d16e6ccc0f6c69307cc4"
     * junopass.projectID = "xxx"
     * 
     * let keys = junopass.setupDevice()
     * let publicKey = keys.publicKey
     * junopass.authenticate("EMAIL", "user@test.com", publicKey).then(function (resp) {
     *      assert.notEqual(resp, null)
     *      assert.notEqual(resp.validChallenge, null)
     *      assert.notEqual(resp.deviceID, null)
     *  }).catch(function (err) {
     *      console.error("Error experienced", err)
     *  })
     */
    authenticate(method, identifier, publicKey) {
        if (!this.accessToken) throw new Error("Access token is required")
        if (!this.projectID) throw new Error("Project ID is required")
        if (!this.junoPassPublicKey) throw new Error("JunoPass Public Key is required")

        if (!method) throw new Error("method is required")
        if (!identifier) throw new Error("identifier is required")
        if (!publicKey) throw new Error("publicKey is required")

        let self = this
        let payload = {
            "method": method,
            "identifier": identifier,
            "public_key": publicKey,
            "project_id": this.projectID
        }

        return client.authenticateRequest(this.accessToken, payload).then(function (resp) {
            let deviceID = resp.device_id
            let challenge = resp.challenge
            let loginRequest = resp.login_request
            let junoPassPublicKey = null
            let verified = null

            junoPassPublicKey = Buffer.from(self.junoPassPublicKey, 'hex')
            challenge = Buffer.from(challenge, 'hex')
            verified = signatures.verifyJunoPassMessage(junoPassPublicKey, challenge)
            if (!verified) throw new Error("Invalid challenge returned")

            let validChallenge = nacl.util.encodeUTF8(verified)
            return {
                validChallenge: validChallenge,
                deviceID: deviceID,
                isLoginRequest: loginRequest
            }

        }).catch(function (err) {
            throw err
        })
    },
    /**
     * Verify OTP message. Send back the user OTP plus a valid challenge obtained in step 1 i.e authenticate function.
     * @param {*} challenge 
     * @param {*} deviceID 
     * @param {*} privateKey 
     * @param {*} otp 
     * 
     * @example:
     *  junopass.verify(challenge, deviceID, devicePrivateKey, otp).then(function (resp) {
     *      // Print all items returned
     *      console.log(res)
     *      let jwtToken = res.access_token
     *      // Save user token and login user normally.
     *      console.log(jwtToken)
     *  }).catch(function (err) {
     *      console.error("Error experienced", err)
     *  })
     */
    verify(challenge, deviceID, privateKey, otp) {
        if (!this.accessToken) throw new Error("Access token is required")
        if (!this.projectID) throw new Error("Project ID is required")
        if (!this.junoPassPublicKey) throw new Error("JunoPass Public Key is required")

        if (!challenge) throw new Error("challenge is required")
        if (!deviceID) throw new Error("deviceID is required")
        if (!privateKey) throw new Error("privateKey is required")

        let self = this
        let payload = null
        let date = new Date()
        let timestamp = date.getTime()
        let message = `${challenge}*${timestamp}`
        if (otp) {
            message = `${challenge}*${timestamp}*${otp}`
        }

        privateKey = nacl.util.decodeBase64(privateKey)
        message = nacl.util.decodeUTF8(message)
        let signedMessage = signatures.signMessage(privateKey, message)

        payload = {
            "device_id": deviceID,
            "signed_hash": signedMessage,
            "project_id": this.projectID
        }

        return client.verifyRequest(this.accessToken, payload).then(function (resp) {
            let accessTokenSigned = resp.access_token_hash
            junoPassPublicKey = Buffer.from(self.junoPassPublicKey, 'hex')
            accessTokenSigned = Buffer.from(accessTokenSigned, 'hex')
            verified = signatures.verifyJunoPassMessage(junoPassPublicKey, accessTokenSigned)
            if (!verified) throw new Error("Invalid access_token_hash returned")

            return resp

        }).catch(function (err) {
            throw err
        })
    }

}