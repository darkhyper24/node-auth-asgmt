const crypto = require('crypto');
function signJWT(payload, secret, expiresIn=3600) {

    const header = {
        alg: 'HS256',
        typ: 'JWT'
    };
    const current_time = Math.floor(Date.now() / 1000);
    const new_payload = {
        ...payload,
        iat: current_time,
        exp: current_time + expiresIn
    };
    const base64UrlEncode = (obj) => {
        return Buffer.from(JSON.stringify(obj))
            .toString('base64')
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');
    };
    const encoded_h= base64UrlEncode(header);
    const encoded_p= base64UrlEncode(new_payload);
    const data = `${encoded_h}.${encoded_p}`;
    const signature = crypto.createHmac('sha256', secret).update(data).digest('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
        return `${encoded_h}.${encoded_p}.${signature}`;
}

const verifyJWT = (token, secret) => {
    const [header, payload, signature] = token.split('.');
    const data = `${header}.${payload}`;
    const expectedSignature = crypto.createHmac('sha256', secret).update(data).digest('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
    if (expectedSignature !== signature) {
        throw new Error('Invalid signature');
    }
    const decodedPayload = JSON.parse(Buffer.from(payload, 'base64').toString('utf8'));
    if (decodedPayload.exp) {
        const currentTime = Math.floor(Date.now() / 1000);
        if (currentTime > decodedPayload.exp) {
            throw new Error('Token expired');
        }
    }
    return decodedPayload;
};
module.exports = { signJWT, verifyJWT };