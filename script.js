const express = require('express');
const app = express();
const path = require('path');
const port=5000;
const mongoose = require('mongoose');
const UserOtp=require("./models/otpVerification");
const User=require("./models/User");

const nodemailer=require('nodemailer');
const bcrypt=require('bcrypt');
const OtpVerification = require('./models/otpVerification');
require('dotenv').config();

app.use(express.static(path.join(__dirname, 'static')));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.set('view engine', 'hbs');

let transporter=nodemailer.createTransport({
    service:"gmail",
    auth:{
        user: process.env.GMAIL_USER,
        pass: process.env.GMAIL_PASS 
    }
})
transporter.verify((error,success)=>{
    if(error){
        console.log(error);
    }else{
        console.log("Ready for msg");
        console.log(success);
    }
})

app.post("/signup",(req,res)=>{
    let{name,email,password}=req.body;
    name=name.trim();
    email=email.trim();
    password=password.trim();

    if(name=="" || email=="" || password==""){
        res.json({
            status:"FAILED",
            message:"Empty input fields",
        });
    }
    else{
        User.find({email}).then((result)=>{
            if(result.length){
                res.json({
                    status:"Failed",
                    message:"User with this email already exists",
                });
            }
            else{
                const saltRounds=10;
                bcrypt.hash(password,saltRounds).then((hashPassword)=>{
                    const newUser=new User({
                        name,
                        email,
                        password:hashPassword,
                        verified:false,
                    });
                    newUser.save().then((result)=>{
                        sendOtpVerificationEmail(result,res);
                    })
                })
            }
        })
        
    }
})
const sendOtpVerificationEmail=async({_id,email},res)=>{
    try{
        const otp=`${Math.floor(1000+Math.random()*9000)}`;
        
        const mailOptions={
            from:process.env.GMAIL_USER,
            to:email,
            subject:"Verify Your Email",
            html:`<p>Enter <b>${otp}</b> in the app to verify your email address</p>
            <p>This code<b> expires in 1 hour</b></p>`,
        };
        const saltRounds=10;
        const hashedOTP=await bcrypt.hash(otp,saltRounds);
        const newOTPVerification=await UserOtp({
            userId:_id,
            otp:hashedOTP,
            createdAt:Date.now(),
            expiresAt:Date.now()+3600000,
        });
        await newOTPVerification.save();
        transporter.sendMail(mailOptions);
        res.json({
            status:"PENDING",
            message:"Verification otp email sent",
            data:{
                userId:_id,
                email,
            },
        })
    }catch(err){
        res.json({
            status:"FAILED",
            message:error.message,
        });
    }
};
app.post("/verifyOTP",async(req,res)=>{
    try{
        let {userId,otp}=req.body;
        if(!userId || !otp){
            throw Error("Empty otp details are not allowed");
        }else{
            const OtpVerificationRecords=await OtpVerification.find({
                userId,
            });
            if(OtpVerificationRecords.length<=0){
                throw new Error("Account doesn't exist or has been verified already");
            }else{
                const{expiresAt}=OtpVerificationRecords[0];
                const hashedOTP=OtpVerificationRecords[0].otp;

                if(expiresAt < Date.now()){
                 await OtpVerification.deleteMany({userId});
                 throw new Error("Code has been expired :(");   
                }else{
                    const validOTP=await bcrypt.compare(otp,hashedOTP);
                    if(!validOTP){
                        throw new Error("Invalid code");
                    }else{
                        await User.updateOne({_id:userId},{verified:true});
                        await OtpVerification.deleteMany({userId});
                        res.json({
                            status:"VERIFIED",
                            message:"Email verified successfully",
                        });
                    }
                }
            }
        }
    }
    catch(error){
        res.json({
            status:"FAILED",
            message:error.message,
        });
    }
})
app.post("/resendOTP",async(req,res)=>{
    try{
        let{userId,email}=req.body;
        if(!userId || !email){
            throw Error("Empty user details are not allowed");
        }else{
            await OtpVerification.deleteMany({userId});
            sendOtpVerificationEmail({_id:userId,email},res);
        }
    }catch(error){
        res.json({
            status:"FAILED",
        });
    }
})
mongoose.connect("mongodb://127.0.0.1:27017/OtpVerification").then(()=>{
    app.listen(port,()=>{
        console.log(`Server running on port ${port}`);
    })    
})

