const mongoose=require('mongoose');
const Schema=mongoose.Schema;

const OtpVerificationSchema=new Schema({
    userId:String,
    otp:String,
    createdAt: Date,
    expiresAt: Date,
});
const OtpVerification=mongoose.model(
    "OtpVerification", OtpVerificationSchema
)
module.exports=OtpVerification;