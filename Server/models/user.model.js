const mongoose = require('mongoose');


const userSchema = new mongoose.Schema({
    sub: String,
    metadata : String,
    name: {
        type: String,
        required: 'Name is required'
    },
    email: {
        type: String,
        required: 'Email is required'
    },
    password: {
        type: String,
        required: 'Password is required'
    },
    pic: {
        type: String,
        default: 'https://styles.redditmedia.com/t5_9gxieb/styles/profileIcon_snoo07c29e1f-35bd-43c1-9c5c-c5cc6588b45b-headshot.png?width=128&height=128&frame=1&auto=webp&crop=128:128,smart&s=f4d494f865d37fa39c2d1d2d489d07969966a55e'
    },
});


const User = mongoose.model('User', userSchema);