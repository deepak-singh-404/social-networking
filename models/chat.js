let mongoose = require("mongoose");
let Schema = mongoose.Schema;

var chat = new Schema(
    {
        sender: {
            type: Schema.Types.ObjectId,
            ref: "user"
        },
        receiver: {
            type: Schema.Types.ObjectId,
            ref: "user"
        },
        groupId: {
            type: Schema.Types.ObjectId,
            ref: "group"
        },
        chatId: String,
        message: {
            type: String,
            trim: true
        },
        file: String,
        name: String,
        type: String,
        photoURL: String
    }, {
    timestamps: true
}
);

var Chat = mongoose.model("chat", chat);

module.exports = Chat;