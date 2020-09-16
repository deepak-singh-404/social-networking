let mongoose = require("mongoose");
let Schema = mongoose.Schema;

var single = new Schema(
    {
        sender: {
            type: Schema.Types.ObjectId,
            ref: "user"
        },
        receiver: {
            type: Schema.Types.ObjectId,
            ref: "user"
        },
        message: {
            type: String,
            trim: true
        },
        name:String,
        photoURL:String
    },{
        timestamps:true
    }
);

 var Single = mongoose.model("single", single);

module.exports = Single;