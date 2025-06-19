import mongoose from "mongoose";

const {Schema,models,model} = mongoose;

const refreshTokenSchema = new Schema({
    token :{
        type: String,
        required : true,
        unique : true
    },
    user:{
        type:mongoose.Schema.Types.ObjectId,
        ref: 'User',
        requored:true
    },
    expiresAt : {
        type:Date,
        required:true
    }
},{timestamps:true})

refreshTokenSchema.index({expiresAt:1},{expiresAfterSeconds:0 })

const RefreshToken = models.RefreshToken||model('RefreshToken',refreshTokenSchema)

export default RefreshToken