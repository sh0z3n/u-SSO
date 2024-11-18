const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

class CryptoService {
    constructor() {
        this.secret = process.env.JWT_SECRET;
    }

    generateToken(payload) {
        return jwt.sign(payload, this.secret, { expiresIn: '1d' });
    }

    verifyToken(token) {
        return jwt.verify(token, this.secret);
    }

    generateRandomString(length) {
        return crypto.randomBytes(length).toString('hex');
    }
    verifyJWT (token , secret) {
        return jwt.verify(token, secret);
    }

    hashPassword(password) {
        return bcrypt.hashSync(password, 10);
    }

    comparePassword(password, hash) {
        return bcrypt.compareSync(password, hash);
    }
    generateJWT(payload ,options={} ) {
        return jwt.sign(payload, this.secret, {
            algorithm: 'HS256',
            expiresIn: '1d',
            ...options});
    }
}