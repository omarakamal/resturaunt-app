
const { Router } = require("express");
const router = new Router();
const mongoose = require('mongoose');
const bcryptjs = require("bcryptjs");
const saltRounds = 10;
const { isLoggedIn, isLoggedOut } = require('../middleware/route-gaurd');


const User = require("../models/User.model");

// GET route ==> to display the signup form to users
router.get("/signup", (req, res) => res.render("auth/signup"));

// POST route ==> to process form data
router.post("/signup", (req, res, next) => {
    // console.log("The form data: ", req.body);

    const { email, password } = req.body;

    if (!email || !password) {
        res.render('auth/signup', { errorMessage: 'All fields are mandatory. Please provide your username, email and password.' });
        return;
    }
    const regex = /(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,}/;
    if (!regex.test(password)) {
        res
            .status(500)
            .render('auth/signup', { errorMessage: 'Password needs to have at least 6 chars and must contain at least one number, one lowercase and one uppercase letter.' });
        return;
    }



    bcryptjs
        .genSalt(saltRounds)
        .then((salt) => bcryptjs.hash(password, salt))
        .then((hashedPassword) => {
            return User.create({
                // username: username
                email,
                // passwordHash => this is the key from the User model
                //     ^
                //     |            |--> this is placeholder (how we named returning value from the previous method (.hash()))
                passwordHash: hashedPassword
            });
        })
        .then((userFromDB) => {
            // console.log("Newly created user is: ", userFromDB);
            res.redirect("/profile");
        })
        .catch(error => {
            if (error instanceof mongoose.Error.ValidationError) {
                res.status(500).render('auth/signup', { errorMessage: error.message });
            } else if (error.code === 11000) {
                res.status(500).render('auth/signup', {
                    errorMessage: 'already an account associated with this email, Please sign in'
                });
            } else {
                next(error);
            }
        }); // close .catch()
}) // close .post()



router.get('/login', (req, res, next) => {
    res.render('/auth/login')
});

router.post('/login',(req,res)=>{
    console.log('SESSION =====> ', req.session);

    const {email,password} = req.body
     if (email === '' || password === '') {
        res.render('auth/login', {
            errorMessage: 'Please enter both, email and password to login.'
        });
        return;
    }

    User.findOne({ email })
    .then(user => {
      if (!user) {
        res.render('auth/login', { errorMessage: 'Email is not registered. Try with other email.' });
        return;
      } else if (bcryptjs.compareSync(password, user.passwordHash)) {
        res.render('user/user-profile',user)
    } else {
        res.render('auth/login', { errorMessage: 'Incorrect password.' });
      }
    })
    .catch(error => next(error));
})

router.get('/test',(req,res)=>{
    res.render('test')
    // User.findOne({email:"OMAOMA"})
    // .then((result)=>{
    //     console.log(result)
    // })
})


router.post('/test',(req,res)=>{
    console.log('req.body ',req.body)
    res.redirect('/test')
})


router.get("/profile", (req, res) => res.render("user/user-profile",{userInSession:req.session.currentUser}));

module.exports = router;