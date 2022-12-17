//jshint esversion:6
require('dotenv').config();
const express = require('express');
const ejs = require('ejs');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const encrypt = require('mongoose-encryption');
const md5 = require('md5');
const bcrypt = require('bcrypt');
const passport = require('passport');
const session = require('express-session');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');
require('https').globalAgent.options.rejectUnauthorized = false;

const saltRounds = 10;

const app = express();
const port = process.env.PORT || 3000;

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
app.set('view engine', 'ejs');

app.use(session({
    secret:"longstring",
    resave:false,
    saveUninitialized:false,
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/secretDB");

const userSchema = new mongoose.Schema({
    username: { type: String},
    password: { type: String},
    googleId: String,
    secret: String,
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);
// const secret = process.env.LONG_STRING;
// userSchema.plugin(encrypt,{secret: secret,encryptedFields:['password']});

const User = new mongoose.model("User",userSchema); 

passport.use(User.createStrategy());

// passport.serializeUser(User.serializeUser());
// passport.deserializeUser(User.deserializeUser());

passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, {
        id: user.id,
        username: user.username,
        picture: user.picture
      });
    });
});
  
passport.deserializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, user);
    });
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/", (req, res) => {
    res.render('home');
});

app.get("/auth/google",
    passport.authenticate("google",{scope: ["profile"]})
)

app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

app.get("/login", (req, res) => {
    res.render('login');
});

app.get("/register", (req, res) => {
    res.render('register');
});

app.get("/secrets",(req, res) => {
    User.find({"secret": {$ne:null}},(err,users) => {
        if(err) {
            console.log(err);
        } else {
            if(users) {
                res.render('secrets', {users: users});
            }
        }
    });

});

app.get("/submit",(req, res) => {
    if(req.isAuthenticated()) {
        res.render('submit');
    } else {
        res.redirect("/login");
    }
});



app.get("/logout",(req, res) => {
    req.logout((err) => {
        if(err) {
            console.log(err);
        } else {
            res.redirect("/");
        }
    });
    
});

app.post("/register", (req, res) => {
    // console.log(req.body.password);
    // bcrypt.hash(req.body.password, saltRounds, (err,hash) => {
    //     if (err) throw err;
    //     User.create({
    //         email: req.body.username,
    //         password: hash
    //     },(err) => {
    //         if (err) throw err;
    //         res.render('secrets');
    //     });
    // });
    console.log(req.body.password);
    User.register({username:req.body.username},req.body.password,(err,user) => {
        if (err) {
            console.log(err);
            return res.redirect('/login');
        } else {
            passport.authenticate("local")(req,res,() => {
                res.redirect('/secrets');
            });
        }

    });


    
});

app.post("/login", (req, res) => {
    // username = req.body.username;
    // const password = req.body.password;
    // User.findOne({email:username},(err, user) => {
    //     if(err){
    //         console.log(err);
    //     } else{
    //         if(user) {
    //             bcrypt.compare(password, user.password,(err,result) =>{
    //                 if(result=== true) {
    //                     res.render('secrets');
    //                 }
    //             });
    //         }
    //     }
    // });

    const user = new User({
        username: req.body.username,
        password: req.body.password,
    });

    req.login(user,(err) => {
        if (err) {
            console.log(err);
        } else {
            passport.authenticate("local")(req,res,() => {
                res.redirect('/secrets');
            });
        }    
    })
});

app.post("/submit",(req,res) => {
    const secret = req.body.secret;
    User.findById(req.user.id, (err, user) => {
        if (err) {
            console.log(err);
        } else {
            if(user){
                user.secret = secret;
                user.save((err) => {
                    if (err) {
                        console.log(err);
                    }
                    res.redirect('/secrets');
                });
            }
        }
    });        
});


app.listen(port,() => {
    console.log(`Server listening on port ${port}`);
});


