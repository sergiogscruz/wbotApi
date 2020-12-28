const express = require('express');
const router = express.Router()
const authMiddlewares = require('../middlewares/auth');

router.use(authMiddlewares);

router.get('/', async (req, res) => {
    res.send({ oks: true, id: req.userId })
})

module.exports = app => app.use('/project', router); 