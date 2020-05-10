import axios from "axios"
import {
    BASE_URL
} from "./constants"

axios.defaults.baseURL = BASE_URL

/**
 * Send authentication request to JunoPass
 * @param {*} access_token 
 * @param {*} payload 
 */
export default function authenticateRequest(access_token, payload) {
    let headers = {
        'Authorization': `Token ${access_token}`,
        'Content-Type': 'application/json'
    }
    return axios.post("authenticate/", data = payload, headers = headers).then(function (resp) {
        return resp.data
    }).catch(function (err) {
        console.log(err)
    })
}

/**
 * Send verification request to JunoPass
 * @param {*} access_token 
 * @param {*} payload 
 */
export default function verifyRequest(access_token, payload) {
    let headers = {
        'Authorization': `Token ${access_token}`,
        'Content-Type': 'application/json'
    }

    return axios.post("verify/", data = payload, headers = headers).then(function (resp) {
        return resp.data
    }).catch(function (err) {
        console.log(err)
    })
}