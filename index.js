import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt"
import session from "express-session";
import passport from "passport";
import { Strategy } from "passport-local";
import env from "dotenv";

env.config();
const app = express();
const port = 3000;
const saltRounds = 10;

const db = new pg.Client({
    user: process.env.DATABASE_USER,
    password: process.env.DATABASE_PASSWORD,
    host: process.env.DATABASE_HOST,
    port: process.env.DATABASE_PORT,
    database: process.env.DATABASE,
});
db.connect();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: {
        maxAge: 1000 * 60 * 60 * 0.5
    }
}));
app.use(passport.initialize());
app.use(passport.session());

app.get("/secrets", (req, res) => {
    if (req.isAuthenticated()) {
        return res.render("secrets.ejs");
    } else {
        return res.redirect("/login")
    }
})

app.get("/", (req, res) => {
    res.render("home.ejs");
});

app.get("/login", (req, res) => {
    res.render("login.ejs");
});

app.get("/register", (req, res) => {
    res.render("register.ejs");
});

app.post("/register", async(req, res) => {
    const email = req.body.username;
    const password = req.body.password;

    try {
        const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [
            email,
        ]);

        if (checkResult.rows.length > 0) {
            res.send("Email already exists. Try logging in.");
        } else {
            const salt = bcrypt.genSaltSync(saltRounds);
            const hash = bcrypt.hashSync(password, salt);
            const result = await db.query(
                "INSERT INTO users (email, salt, hash) VALUES ($1, $2, $3) returning *", [email, salt, hash]
            );
            const user = result.rows[0];
            return req.login(user, (err) => {
                if (err) {
                    console.error(err)
                }
                return res.redirect("/secrets");
            })
        }
    } catch (err) {
        console.error(err);
    }
    return res.redirect("/login")
});

app.post("/login", passport.authenticate("local", {
    successRedirect: "/secrets",
    failureRedirect: "/login"
}));

passport.use(new Strategy(async function verify(username, password, cb) {
    try {
        const result = await db.query("SELECT * FROM users WHERE email = $1", [
            username,
        ]);
        if (result.rows.length > 0) {
            const user = result.rows[0];
            if (bcrypt.compareSync(password, user.hash)) {
                return cb(null, user)
            } else {
                return cb(null, false)
            }
        } else {
            return cb("User not found")
        }
    } catch (err) {
        return cb(err);
    }
}))

passport.serializeUser((user, cb) => {
    cb(null, user);
})

passport.deserializeUser((user, cb) => {
    cb(null, user);
})

app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});