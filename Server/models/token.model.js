// token schema to store session token fy db

const mongoose = require('mongoose');
const tokenSchema = new mongoose.Schema({
    userId : { type : mongoose.Schema.Types.ObjectId, ref : 'User' },
    acessToken : String,
    refreshToken : String,
    authCode : String,
    expiresAt : Date,
    scope : [String],
    createdAt : { type : Date, default : Date.now } // tho mongodb will add this field automatically but just in case

});

const Token = mongoose.model('Token', tokenSchema);