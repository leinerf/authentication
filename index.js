import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt"
import session from "express-session";
import passport from "passport";
import { Strategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth2"
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

app.get("/secrets", async(req, res) => {
    if (req.isAuthenticated()) {
        console.log(req.user);
        const result = await db.query("select secret from users where uid=$1", [req.user.uid])
        const secret = result.rows[0].secret;
        return res.render("secrets.ejs", { secret: secret || "You should submit a secret" });
    } else {
        return res.redirect("/login")
    }
})

app.get("/submit", (req, res) => {
    if (req.isAuthenticated()) {
        res.render("submit.ejs")
    } else {
        return res.redirect("/login")
    }
})

app.post("/submit", async(req, res) => {
    if (req.isAuthenticated()) {
        try {
            await db.query("update users set secret=$1 where uid=$2", [req.body.secret, parseInt(req.user.uid)])

            return res.redirect("/secrets")
        } catch (err) {
            console.error(err)
            return res.send("Something went wrong with submitting secret")
        }
    }
    return res.redirect("/")
})

app.get("/", (req, res) => {
    res.render("home.ejs");
});

app.get("/auth/google/", passport.authenticate("google", {
    scope: ["profile", "email"],
}));

app.get("/auth/google/secrets",
    passport.authenticate("google", {
        successRedirect: "/secrets",
        failureRedirect: "/login",
    })
);

app.get("/login", (req, res) => {
    res.render("login.ejs");
});

app.get("/logout", (req, res) => {
    return req.logout((err) => {
        if (err) {
            console.error(err);
        }
        return res.redirect("/")
    });
})

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
                "INSERT INTO users (email, password) VALUES ($1, $2) returning *", [email, password]
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

passport.use("local", new Strategy(async function verify(username, password, cb) {
    try {
        const result = await db.query("SELECT * FROM users WHERE email = $1", [
            username,
        ]);
        if (result.rows.length > 0) {
            const user = result.rows[0];
            if (bcrypt.compareSync(password, user.password)) {
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

passport.use("google", new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
}, async(accessToken, refreshToken, profile, cb) => {
    console.log(profile);
    try {
        const result = await db.query("select * from users where email=$1", [profile.email]);
        if (result.rows.length === 0) {
            const newUser = await db.query("INSERT INTO users (email, password) VALUES ($1, $2) returning *", [profile.email, "google"])
            cb(null, newUser.rows[0])
        } else {
            cb(null, result.rows[0])
        }
    } catch (err) {
        cb(err)
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