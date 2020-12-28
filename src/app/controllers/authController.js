const express = require('express');
const User = require('../models/user');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const authConfig = require('../../config/auth.json');
const crypto = require('crypto');
const mailer = require('../modules/mailer');

function generateToken(param = {}) {
    return jwt.sign(param, authConfig.secret, {
        expiresIn: 86400,
    });
}

router.post('/register', async (req, res) => {
    const {
        email
    } = req.body
    try {
        if (await User.findOne({
                email
            }))
            return res.status(400).send({
                error: "User alredy exists"
            });
        const user = await User.create(req.body);

        user.password = undefined;

        return res.send({
            user,
            token: generateToken({
                id: user.id
            })
        })
    } catch (err) {
        return res.status(400).send({
            error: 'Registration failed',
            messagem: err
        });
    }
});

router.post('/authenticate', async (req, res) => {
    const {
        email,
        password
    } = req.body;

    const user = await User.findOne({
        email
    }).select('+password');

    if (!user)
        return res.status(400).send({
            error: 'User not found'
        });

    if (!await bcrypt.compare(password, user.password))
        return res.status(400).send({
            error: 'Invalid password'
        });

    user.password = undefined

    return res.send({
        user,
        token: generateToken({
            id: user.id
        })
    })

});

router.post('/forgot_password', async (req, res) => {
    const {
        email
    } = req.body;
    try {
        const user = await User.findOne({
            email
        });

        if (!user)
            return res.status(400).send({
                error: 'User not found'
            })

        const token = crypto.randomBytes(20).toString('hex');

        const now = new Date();
        now.setHours(now.getHours() + 1);

        await User.findByIdAndUpdate(user.id, {
            '$set': {
                passwordResetToken: token,
                passwordResetExpires: now
            }
        })

        mailer.sendMail({
            to: email,
            from: 'sergiogscruz@gmail.com',
            template: 'auth/forgot_password',
            context: {
                token
            },
        }, (error) => {
            if (error)
                return res.status(400).send({
                    error: 'Cannot send forgot password'
                })
            return res.send()
        })

    } catch (error) {
        res.status(400).send({
            error: "Error on forgot password",
            messagem: error
        })
    }
})

router.post('/reset_password', async (req, res) => {
    const { email, token, password } = req.body;
    
    try {
        const user = await User.findOne({ email })
            .select('+passwordResetToken passwordResetExpires');
          
        if (!user) 
            return res.status(400).send({ error: 'User not found' });

        if (token !== user.passwordResetToken)
            return res.status(400).send({ error: 'Token invalid' });

        const now = new Date();
        
        if (now > user.passwordResetExpires)
            return res.status(400).send({ error: 'Token expired, gererate a new one' }) 

        user.password = password;

        await user.save();

        res.send();

    } catch (error) {
        return res.status(400).send({ error: 'Cannot reset password, try again'});
    }
})

module.exports = app => app.use('/auth', router);