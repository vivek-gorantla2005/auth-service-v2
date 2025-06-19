import mongoose from "mongoose";
import logger from "./logger.js";

export default async function connectMongoDB() {
    try{
        const conn = await mongoose.connect(process.env.MONGODB_URI);
        logger.warn(`connected to DB : ${conn.connection.host}`);
    }catch(err){
        logger.warn('error connecting to mongoDB');
        process.exit(1);
    }
}

