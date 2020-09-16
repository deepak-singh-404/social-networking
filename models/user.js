var mongoose = require('mongoose');
var Schema = mongoose.Schema;
var User = new Schema({
    firstName: {
        type: String,
        lowercase: true,
        trim: true,
        required: [true]
    },
    lastName: {
        type: String,
        lowercase: true,
        trim: true,
        required: [true, "lastName is required"]
    },
    email: {
        type: String,
        unique: true,
        lowercase: true,
        trim: true,
        required: [true, "email is required"]
    },

    password: {
        type: String,
        trim: true,
        required: [true, "password is required"]
    },
    photoURL: String,
    resetToken: String,
    friends: [
        {
            type: Schema.Types.ObjectId,
            ref: "user",
        }
    ],
    group: [
        {
            type: Schema.Types.ObjectId,
            ref: "group",
        }
    ],
    socketId:String

}, { timestamps: true });

var User = mongoose.model('user', User);

module.exports = User;