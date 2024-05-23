const express = require("express");
const bcrypt = require("bcrypt");
const router = express.Router();
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer')
const User = require("../models/UserSchema");
require("dotenv").config();

//Sign Up route
router.post("/signup", async (req, res) => {
    const { username, email, password } = req.body;
    const user = await User.findOne({ email });
  
    if(user) {
      return res.json({ message: "User already exists" });
    }
  
    const hashedPassword = await bcrypt.hash(password, 10);
  
    const newUser = new User({
      username,
      email,
      password: hashedPassword,
    });
    await newUser.save();
    return res.json({ status: true, message: "New user created successfully" });
  });


  //Login route
  router.post("/login", async (req, res) => {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
  
    //user found in db
    if (!user) {
      return res.json({ message: "user not found create new account" });
    }
  
    const validPassword = await bcrypt.compare(password, user.password);
  
    // user not found in db
    if (!validPassword) {
      return res.json({ message: "Password incorrect" });
    }
  
    //if valid password then generate token
    const token = jwt.sign({ username: user.username }, process.env.KEY, {
      expiresIn: "1h"
    })
    res.cookie("token", token, { httpOnly: true, maxAge: 3600000 });
    return res.json({ status: true, message: "Logged in successfully" });
  });


  //Forgot password route
  router.post('/forgotPassword', async (req, res) => {
    const { email } = req.body;
    try {
      const user = await User.findOne({ email });
      if(!user) {
        return res.json({ message: "User not Registered" });
      }
  
      const token = jwt.sign({ id: user._id }, process.env.KEY, { expiresIn: '15m' })
  
      let transporter = nodemailer.createTransport({
        service: "gmail",
        auth: {
          user: process.env.EMAIL,
          pass: process.env.PASSWORD,
        }
      });
  
      let mailOptions = {
        from: process.env.EMAIL,
        to: email,
        subject: "Reset Password",
        text: `http://localhost:5173/resetPassword/${token}`,
      };
  
      transporter.sendMail(mailOptions, function (error, info) {
        if (error) {
          return res.json({ message: "Error sending email" })
        } else {
          return res.json({ status: true, message: "email sent" })
        }
      });
    } catch (err) {
      console.log(err.message);
    }
  });


  //Reset password
  router.post('/resetPassword/:token', async(req, res) => {
    const {token} = req.params;
    const {password} = req.body;
    try{
      const decoded = await jwt.verify(token, process.env.KEY);
      const id = decoded.id;
      const hashedPassword = await bcrypt.hash(password, 10)
      await User.findByIdAndUpdate({_id: id}, {password: hashedPassword});
      return res.json({status: true, message: "Updated new password"})
    } catch(err) {
      return res.json('invalid token')
    }
  })

  //verify user
  const verifyUser = async (req, res, next) => {
    try {
      const token = req.cookies.token;
      if(!token) {
        return res.json({status: false, message: "no token"})
      }
      const decoded = await jwt.verify(token, process.env.KEY)
      next()
    } catch(err) {
      return res.json(err)
    }

  }

  router.get('/verify', verifyUser, (req, res) => {
    return res.json({status: true, message: 'authorized'})
  })

  router.get('/logout', (req, res) => {
    res.clearCookie('token')
    return res.json({status: true})
  })




  module.exports = router;