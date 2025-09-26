const mongoose = require('mongoose');


const connectDb = async () => {
    await mongoose.connect(process.env.DATABASE_URL, {
        dbName: 'auth-system'
    }).then(() => {
        console.log("MongoDB connected successfully");
    }).catch((err) => {
        console.log("MongoDB connection error: ", err);
        process.exit(1);
    }); 
}

module.exports = {connectDb}

