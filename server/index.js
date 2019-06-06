const express = require('express');
const massive = require('massive');
const session = require('express-session');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const {SERVER_PORT, CONNECTION_STRING, SESSION_SECRET} = process.env;

const app = express();

app.use(express.json());

massive(CONNECTION_STRING).then(db => {
    app.set('db', db);
    console.log('Database Connected');
})

app.use(session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: {
        maxAge: 1000 * 60 * 60 * 24
    }
}))

//register, login, logout
app.post('/auth/register', async function(req, res) {
    const {username, password} = req.body;
    const db = req.app.get('db');
    db.checkForUser(username).then(users => {
        if(users.length === 0) {
            const salt = bcrypt.genSalt(10);
            bcrypt.hash(password, salt).then(hash => {
                db.addUser(username, hash).then(() => {
                    req.session.user = username;
                    res.status(200).json(req.session.user);
                })
            })
        } else {
            res.status(409).json({error: "Username Taken"});
        }
    })
})

app.post('/auth/login', async function(req, res) {
    const {username, password} = req.body;
    const db = req.app.get('db');
    const hash = await db.checkUser(username);
    console.log(hash[0].password);
    bcrypt.compare(password, hash[0].password).then(doesMatch => {
        if(doesMatch === true) {
            req.session.user = username;
            res.status(200).json(req.session.user);
        } else {
            res.status(403).json({error: "Incorrect Username or Password"})
        }
    })
    // console.log(doesMatch);
})

app.listen(SERVER_PORT, () => console.log(`Listening on Port ${SERVER_PORT}`));