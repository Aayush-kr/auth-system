const jwt = require('jsonwebtoken');
const User = require('../models/User');
const { redisClient } = require('../config/redisConfig');

const isAuthenticated = async (req, res, next) => {
        try {
            if(!req.cookies.accessToken) {
                return res.status(403).json({
                    message: 'Please login - No token'
                })
            }
            const decoded = await jwt.verify(req.cookies.accessToken, process.env.ACCESS_TOKEN_SECRET);
            if(!decoded) {
                return res.status(400).json({message: "Token expired"}); 
            }
            const cache = await redisClient();
            const cachedUser = await cache.get(`user:${decoded?._id}`);
            if(cachedUser) {
                req.user = JSON.parse(cachedUser);
                next();
            }
            const user = await User.findById(decoded?._id).select("-password");
            if(!user) {
                return res.status(400).json({message: "User not exist"}); 
            }
            await cache.setEx(`user:${decoded?._id}`, 3600, JSON.stringify(user))
            req.user = user;
            next();
        } catch (error) {
            return res.status(401).json({message: error.message}); 
        }
           
}

module.exports = {isAuthenticated}