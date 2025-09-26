const JWT = require('jsonwebtoken');
const { redisClient } = require('../config/redisConfig');

const generateTokens = async (_id, res) => {
   const accessToken = await JWT.sign({_id}, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '5m'});
   const refreshToken = await JWT.sign({_id}, process.env.REFRESH_TOKEN_SECRET, { expiresIn: '7d'});
   const refreshTokenKey = `refresh-token:${_id}`
   const cache = await redisClient();
   cache.setEx(refreshTokenKey, 7 * 24 * 60 * 60,  refreshToken);

    // Set refresh token as an httpOnly cookie
    res.cookie('accessToken', accessToken, {
        httpOnly: true, // Prevents client-side JavaScript from accessing it
        secure: process.env.NODE_ENV === 'production', // Use secure in production (HTTPS)
        maxAge: 1 * 60 * 1000,
        sameSite: 'strict', // Or 'Strict' depending on your requirements
    });

    res.cookie('refreshToken', refreshToken, {
        httpOnly: true, // Prevents client-side JavaScript from accessing it
        secure: process.env.NODE_ENV === 'production', // Use secure in production (HTTPS)
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days in milliseconds
        sameSite: 'strict', // Or 'Strict' depending on your requirements
    });
}

const verifyRefreshToken = async (refreshToken) => {
    const decoded = await JWT.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
    const cache = await redisClient()
    const cachedRefreshToken = await cache.get(`refresh-token:${decoded._id}`)
    if( cachedRefreshToken === refreshToken) {
        return decoded;
    }
    return null;
}

const generateAccessToken = async (_id, res) => {
    const accessToken = await JWT.sign({_id}, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '5m'});
    res.cookie('accessToken', accessToken, {
        httpOnly: true, // Prevents client-side JavaScript from accessing it
        secure: process.env.NODE_ENV === 'production', // Use secure in production (HTTPS)
        maxAge: 1 * 60 * 1000,
        sameSite: 'strict', // Or 'Strict' depending on your requirements
    });
}




module.exports = {generateTokens, verifyRefreshToken, generateAccessToken}