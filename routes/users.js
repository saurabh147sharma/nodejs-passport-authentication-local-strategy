const express = require('express');
const router = express.Router();

 const passport = require('passport');
 const LocalStrategy = require('passport-local').Strategy;

const User = require('../models/users');

router.get('/register',(req,res)=>{
    res.render('register');
});

router.get('/login',(req,res)=>{
    res.render('login');
});

router.post('/register',(req,res)=>{
    var userName = req.body.userName;
    var email = req.body.email;
    var password = req.body.password;
    var confPassword = req.body.confPassword;
    
    req.checkBody('userName','Name is required').notEmpty();
    req.checkBody('email','Email is required').notEmpty();
    req.checkBody('email','Email is not valid').isEmail();
    req.checkBody('password','Password is required').notEmpty();
    req.checkBody('confPassword','Confirm password is required').notEmpty();
    req.checkBody('confPassword','Confirm password does not match').equals(req.body.password);

    var errors = req.validationErrors();
    if(errors){
        res.render('register',{
            errors
        });
    }
    else{
        var newUser = new User({
            userName,
            email,
            password
        });

        User.createUser(newUser,(error,user)=>{
            if(error) throw error;
        });

        req.flash('success_msg','Registered successfully!');
        res.redirect('/users/login');
    }
});

passport.use(new LocalStrategy(
    (email, password, done)=>{
        User.getUserByEmail(email, (err, user)=>{
            if(err) throw err;
            if(!user){
                return done(null, false, {message: 'Invalid login credentials'});
            }
            User.comparePassword(password, user.password, (err, isMatch)=>{
                if(err) throw err;
                if(isMatch){
                    return done(null, user);
                }
                else{
                    return done(null, false, {message: 'Invalid password'});
                }
            });
        });
    }
));


passport.serializeUser((user,done)=>{
    done(null, user.id);
});

passport.deserializeUser((id,done)=>{
    User.getUserById(id,(err,user)=>{
        done(err,user);
    });
});

router.post('/login',
passport.authenticate('local', { successRedirect: '/', failureRedirect: '/users/login', failureFlash: true }),
 (req, res)=> {
    res.redirect('/');
});


router.get('/logout', function (req, res) {
	req.logout();

	req.flash('success_msg', 'You are logged out');

	res.redirect('/users/login');
});


module.exports = router;