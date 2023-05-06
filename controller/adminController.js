const Admin = require('../models/Admin');

const addAdmin = async (req, res) => {
    const admin = new Admin(req.body)

    try {
        await admin.save()
        const token = await admin.generateAuthToken()
        res.status(201).send({ admin: admin, token })
    } catch (e) {
        res.status(400).send(e)
    }

}

const loginAdmin = async (req, res) => {

    try {
        console.log('dkhalit lil controller', req.body.email);
        const admin = await Admin.findByCredentials(req.body.email, req.body.password)
        const token = await admin.generateAuthToken()
        console.log('token', token);
        res.cookie('token', token, {
            httpOnly: true,
            sameSite: 'lax',
            secure: false,
            maxAge: 30 * 24 * 60 * 60 * 1000,
        }, () => {
            console.log('cookie set successfully');
        });
        res.send('Success');
    } catch (e) {
        res.sendStatus(400)
    }
}
const logoutCurrentSessionAdmin = async (req, res) => {
    try {
        req.admin.tokens = req.admin.tokens.filter((token) => {
            return token.token !== req.token
        })
        console.log(req.admin.tokens);
        await req.admin.save()
        res.cookie('token', '', { expires: new Date(0) });
        res.send('logout with success');
    } catch (e) {
        res.sendStatus(500)
    }
}

const logoutAllSessionAdmin = async (req, res) => {
    try {
        req.admin.tokens = []
        console.log('nahna fil logoutAll')
        await req.admin.save()
        res.send()
    } catch (e) {
        res.status(500).send()
    }
}
module.exports = {
    addAdmin,
    loginAdmin,
    logoutCurrentSessionAdmin,
    logoutAllSessionAdmin
};

