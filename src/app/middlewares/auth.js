const jwt = require('jsonwebtoken');
const authConfig = require('../../config/auth.json')

module.exports = (req, res, next) => {
    const authHeader = req.headers.authorization;

    if (!authHeader)
        return res.status(401).send({ error: 'No token provided' });

    const parts = authHeader.split(' ');
    const [ scheme, token ] = parts;

    if (parts.length != 2)
        return res.status(401).send({ error: 'Token error'})

    if (!/^Bearer$/i.test(scheme))
        return res.status(401).send({error: 'Token malformated'})

    jwt.verify(token, authConfig.secret, (error, decoded) => {
        if (error) return res.status(401).send({ error: 'Token invalid'})

        req.userId = decoded.id;
        return next();
    })
}