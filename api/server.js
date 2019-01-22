const express = require('express');
const helmet = require('helmet');
const knex = require('knex');
const bcrypt = require('bcrypt');
const session = require('express-session');
const KnexSessionStore = require('connect-session-knex')(session);
const { protected, check } = require('../middleware/main');
const randomstring = require('randomstring');

const knexConfig = require('../knexfile');

const server = express();
const db = knex(knexConfig.development);

const sessionConfig = {
    secret: randomstring.generate(256),
    cookie: {
        maxAge: 1000 * 60 * 5,
        secure: false,
    },
    httpOnly: true,
    resave: false,
    saveUninitialized: false,
    store: new KnexSessionStore({
        tablename: 'sessions',
        sidfieldname: 'sid',
        knex: db,
        createtable: true,
        clearInterval: 1000 * 60 * 10,
    }),
};

server.use(helmet());
server.use(express.json());
server.use(session(sessionConfig));

server.get('/', (req, res) => {
    res.send('sanity check');
});

server.post('/api/register', check, (req, res) => {
    const userInfo = req.body;
    if (userInfo.password.length < 32) {
        res.status(400).json({
            message: 'Password must be at least 32 characters long.',
        });
        return;
    }

    const hash = bcrypt.hashSync(userInfo.password, 12);

    userInfo.password = hash;

    db('users')
        .insert(userInfo)
        .then(id => {
            res.status(201).json(id);
        })
        .catch(err => {
            console.log(err);
            res.status(500).json(err);
        });
});

server.post('/api/login', (req, res) => {
    const creds = req.body;

    db('users')
        .where({ username: creds.username })
        .first()
        .then(user => {
            if (user && bcrypt.compareSync(creds.password, user.password)) {
                req.session.user = user;
                res.status(200).json({ success: "You're good to go!" });
            } else {
                res.status(401).json({
                    failure: 'Incorrect username or password',
                });
            }
        })
        .catch(err => res.status(500).json(err));
});

server.get('/api/users', protected, (req, res) => {
    db('users').then(response => {
        res.status(200).json(response);
    });
});

module.exports = server;
