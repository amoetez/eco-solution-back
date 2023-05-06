const jwt = require('jsonwebtoken')
const Admin = require('../models/Admin')

const auth = async (req, res, next) => {
    try {
        // const token = req.header('Authorization').replace('Bearer ', '')
        // const token = req.token.replace('Bearer ', '');
        // console.log(token);
        console.log('nahna fil auth');
        console.log('hedha token mil auth', req.cookies.token);
        const decoded = jwt.verify(req.cookies.token, 'thisIsMySecretMessage')
        console.log('decoded', decoded);
        console.log('t3adit');
        const admin = await Admin.findOne({ _id: decoded._id, 'tokens.token': req.cookies.token })
        console.log('admin mil middleware', admin);
        console.log('hata lina');
        

        if (!admin) {
            throw new Error()
        }

        req.token = req.cookies.token;
        req.admin = admin
        console.log('token, admin',req.token);
        next()
    } catch (e) {
        res.status(401).send({ error: 'Please make sure that you gave the right credentials.' })
    }
}

module.exports = auth

