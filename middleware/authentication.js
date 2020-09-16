const jwt = require('jsonwebtoken');
const key = 'thisismysecretkey';

async function createToken(user) {
    const token = await jwt.sign({
        id: user.id,
        email: user.email,
        exp: Math.floor(Date.now() / 1000) + (60 * 60 * 24),
    }, key);
    return token;
}
async function validateToken(req, res, next) {
    try {
        var token = req.cookies.token || req.headers['authorization'] || req.body['authorization'];
        const payload = await jwt.verify(token, key);
        req.user = {
            id: payload.id,
            email: payload.email
        }
        next();
    } catch (error) {
        console.log(error);
        if (error.name === 'TokenExpiredError') {
            return res.status(403).send('Token is expired,please login again');
        }
        return res.status(403).send('invalid token');
    }
}

module.exports = {
    createToken,
    validateToken
}