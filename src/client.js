import axios from "axios"
import constants from "./constants"

axios.defaults.baseURL = constants.BASE_URL

/**
 * Send authentication request to JunoPass
 * @param {*} access_token 
 * @param {*} payload 
 */
function authenticateRequest(access_token, payload) {
    let headers = {
        'Authorization': `Token ${access_token}`,
        'Content-Type': 'application/json'
    }
    return axios.post("user/authenticate/", payload, {
        headers: headers
    }).then(function (resp) {
        return resp.data
    }).catch(function (err) {
        throw new Error(err.response.data)
    })
}

/**
 * Send verification request to JunoPass
 * @param {*} access_token 
 * @param {*} payload 
 */
function verifyRequest(access_token, payload) {
    let headers = {
        'Authorization': `Token ${access_token}`,
        'Content-Type': 'application/json'
    }

    return axios.post("user/verify/", payload, {
        headers: headers
    }).then(function (resp) {
        return resp.data
    }).catch(function (err) {
        throw new Error(err.response.data)
    })
}

export default {
    authenticateRequest: authenticateRequest,
    verifyRequest: verifyRequest
}