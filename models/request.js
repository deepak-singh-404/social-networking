let mongoose = require("mongoose");
let Schema = mongoose.Schema;

var Request = new Schema(
    {
        sender:
        {
            type: Schema.Types.ObjectId,
            ref: "user"
        },
        receiver:
        {
            type: Schema.Types.ObjectId,
            ref: "user"
        },
        isAccepted: {
            type: Boolean,
            default: false
        },
        isReject: {
            type: Boolean,
            default: false
        },
        groupId: {
            type: Schema.Types.ObjectId,
            ref: "group"
        }
    },
    { timestamps: true }
);

var Request = mongoose.model("Request", Request);

module.exports = Request;