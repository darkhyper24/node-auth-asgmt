const crypto = require('crypto');


function hashPassword(password) {
    const salt = crypto.randomBytes(16).toString('hex');
    const iterations = 10000;
    const keylen = 64;
    const digest = 'sha512';
    const hash = crypto.pbkdf2Sync(password, salt, iterations, keylen, digest).toString('hex');
    return `${salt}:${hash}`;
}

function verifyPassword(password, hashedPassword) {
    const [salt,hash] = hashedPassword.split(':');
    const iterations = 10000;
    const keylen = 64;
    const digest = 'sha512';
    const hashing = crypto.pbkdf2Sync(password, salt, iterations, keylen, digest).toString('hex');
    if (hashing === hash) {
        return true;
    }
    return false;
}

module.exports = { hashPassword,verifyPassword };