# JunoPass-js

## Installation

### Using Yarn

    yarn add junopass-js

### Using NPM

    npm install junopass-js


## How to authenticate

### Step 1

Submit authentication details to JunoPass. Verify signed challenge hash for authenticity.

    junopass.accessToken = "xxx"
    junopass.junoPassPublicKey = "ae7b59d370ec4d04011baf2738ef068cb1dde6d22e55d16e6ccc0f6c69307cc4"
    junopass.projectID = "xxx"

    let keys = junopass.setupDevice()
    let publicKey = keys.publicKey
    junopass.authenticate("EMAIL", "user@test.com", publicKey).then(function (resp) {
        console.log(resp.deviceID)
        console.log(resp.validChallenge)
    }).catch(function (err) {
        console.error("Error experienced", err)
    })

### Step 2

Use the challenge and device ID returned from step  1 plus the user sent OTP token to verify registration/login request. OTP token will be automatically sent to the user through SMS or email after completing step 1.

    junopass.verify(challenge, deviceID, devicePrivateKey, otp).then(function (resp) {
        // Print all items returned
        console.log(res)
        let jwtToken = res.access_token
        // Save user token and login user normally.
        console.log(jwtToken)
    }).catch(function (err) {
        console.error("Error experienced", err)
    })

### Generating device keys

Use this during setup/registration. Consider keeping the keys in a safe place for future use.
**Note the private_key must never be shared. We recommend keeping it in a secure key store. Send all your requests through using secure network protocol i.e https**

    let keys = junopass.setupDevice()
    console.log(keys.secretKey)
    console.log(keys.publicKey)


## Running Tests

    npm test

