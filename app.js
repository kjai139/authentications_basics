/////// app.js

const express = require("express");
const path = require("path");
const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const mongoose = require("mongoose");
const Schema = mongoose.Schema;
const bcrypt = require('bcryptjs')
require('dotenv').config()
const debug = require('debug')('authentication_basics:*')
//this how u set it for whole app

const mongoDb = process.env.MONGODB_LOGIN;
mongoose.connect(mongoDb, { useUnifiedTopology: true, useNewUrlParser: true });
const db = mongoose.connection;
db.on("error", console.error.bind(console, "mongo connection error"));

const User = mongoose.model(
  "User",
  new Schema({
    username: { type: String, required: true },
    password: { type: String, required: true }
  })
);

const app = express();
app.set("views", __dirname);
app.set("view engine", "ejs");

app.use(session({ secret: "cats", resave: false, saveUninitialized: true }));

passport.use(
    new LocalStrategy(async(username, password, done) => {
      try {
        const user = await User.findOne({ username: username });
        if (!user) {
          return done(null, false, { message: "Incorrect username" });
        };
        const passwordsMatch = await bcrypt.compare(password, user.password)
        
        if (passwordsMatch) {
          return done(null, user);
        } else {
          return done(null, false, {message: 'Incorrect Password'})
        }
        
      } catch(err) {
        return done(err);
      };
    })
);

passport.serializeUser(function(user, done) {
    done(null, user.id);
  });
  //serialize defines how the object should be serialized into a format that can be stored into the session such as a unique id

  //deserialize is called only once during the authentication process which is right after the user is authenticated and reconstructing the user object. when it's done it will be in the req.user
  passport.deserializeUser(async function(id, done) {
    try {
      const user = await User.findById(id);
      done(null, user);
      //in the done call back object first arg is error and second arg
    } catch(err) {
      done(err);
    };
});


app.use(passport.initialize());
//this must be called before route handlers that use passport functionality
app.use(passport.session());
//this is a function that looks for express session middleware specifically that you have to set up
app.use(express.urlencoded({ extended: false }));
//this line is for viewtemplate backend to backend with key-value pairs encoded

// this makes it so that currentUser can be accessed in all views and app. App use without route will run everytime any req is made
app.use(function(req, res, next) {
    res.locals.currentUser = req.user;
    next();
});

app.get("/", (req, res) => res.render("index", {
    user:req.user
}));
app.get('/sign-up', (req, res, next) => {
    res.render('sign-up-form')
    debug('in sign up')
})
app.post("/sign-up", async (req, res, next) => {

    const {username, password} = req.body
    try {
      const salt = await bcrypt.genSalt(10)
      const hashedPassword = await bcrypt.hash(password, salt)

      const newUser = new User({
        username: username,
        password: hashedPassword
      })

      await newUser.save()
      debug('user successfully registered')
      res.redirect('/')
    } catch(err) {
      return next(err);
    };
});

app.post(
    "/log-in",
    passport.authenticate("local", {
      successRedirect: "/",
      failureRedirect: "/"
    })
);

app.get("/log-out", (req, res, next) => {
    req.logout(function (err) {
      if (err) {
        return next(err);
      }
      res.redirect("/");
    });
});

app.listen(3000, () => console.log("app listening on port 3000!"));