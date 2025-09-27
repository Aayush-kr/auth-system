const sanitize = require('mongo-sanitize');
const { validateRegister, getAllErrors, validateLogin }  =  require('../utils/validator');
const {TryCatch} = require('../middleware/TryCatch');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const User = require('../models/User');
const { redisClient } = require('../config/redisConfig');
const { sendMail } = require('../utils/sendEmail');
const { getVerifyEmailHtml, getOtpHtml } = require('../utils/html');
const { generateVerifyToken, generateOTP } = require('../utils/generateKeys');
const { generateTokens, verifyRefreshToken, generateAccessToken } = require('../utils/generateToken');

const registerUser = TryCatch( async (req,res) => {
    
    const sanitizedBody = sanitize(req.body);
    const validation = validateRegister.safeParse(sanitizedBody);
    if(!validation.success) {
        const {errorMsg, allErrors} = getAllErrors(validation)
        return res.status(400).json({
            message: errorMsg,
            error: allErrors
        })

    }
    const {name, email, password} = validation.data;
    const cache = await redisClient();
    
    const rateLimitKey = `register-rate-limit:${req.ip}:z${email}`;

    if(await cache.get(rateLimitKey) ){
        return res.status(429).json({
            message: 'Too many requests, try again later'
        })

    }
    const existingUser = await User.findOne({ email });
    if(existingUser) {
        return res.status(400).json({
            message: 'User already exist, Please login'
        })
    }

    const verifyToken = generateVerifyToken();
    const hashedPassword = await bcrypt.hash(password,10);
    const verifyKey = `verify:${verifyToken}`;
    const dataToStore = JSON.stringify({
        name,
        email,
        password : hashedPassword 
    })

    await cache.set(verifyKey, dataToStore, {EX: 300});

    const subject = "Verify your email for account creation";
    const html = getVerifyEmailHtml({email, verifyToken})
    const text = ``;

    await sendMail(email,subject, text, html);
    await cache.set(rateLimitKey,"true", {EX: 60});

    return res.json({
        message: "If you email is valid, a verification link has been sent. It will expire in 5 minutes"
    })

})

const verifyUser = TryCatch(async (req,res) => {
    const token = req.params.verifyToken;
    if(!token) {
        return res.status(401).json({
            message: "Invalid token"
        })
    }
    const cache = await redisClient();
    const verifyKey = `verify:${token}`;
    const userData = await cache.get(verifyKey)
    if(!userData) {
          return res.status(401).json({
            message: "Token Expired"
        })
    }

await User.create( JSON.parse(userData) );
    return res.status(200).json({
        message: 'User registered sucessfully'
    })

})


const loginUser = TryCatch(async(req, res) => {
    const sanitizedBody = sanitize(req.body);
    const validation = validateLogin.safeParse(sanitizedBody);
    if(!validation.success) {
        const {errorMsg, allErrors} = getAllErrors(validation)
        return res.status(400).json({
            message: errorMsg,
            error: allErrors
        })
    }
    const cache = await redisClient();
    const {email, password} = validation?.data;
    const user = await User.findOne({email});
    if(!user) {
        return res.status(400).json({
            message: "User not exist",
        })
    }

    
    const isValidPassword = await bcrypt.compare(password, user.password)
    if(!isValidPassword) {
        return res.status(400).json({
            message: "Invalid credentials",
        })
    }

    const otp = generateOTP();
    const otpKey = `otp:${email}:${otp}`
    const rateLimitKey = `login-rate-limit:${req.ip}:${email}`;

    if(await cache.get(rateLimitKey)) {
          return res.status(429).json({
            message: 'Too many requests, try again later'
        })
    }

    const subject = "OTP for login user";
    const html = getOtpHtml({email, otp})
    const text = ``;

    await cache.set(otpKey, "true", {EX: 300});
    await sendMail(email,subject, text, html);
    await cache.set(rateLimitKey, "true", {EX: 300});

    return res.json({
        message: 'OTP sent to your registered email. It will be valid for 5 minutes'
    })

});

const verifyOtp = TryCatch( async (req,res) => {
    const { otp, email }= req.body;
    if(!otp) {
        return res.status(400).json({
            message: "Please enter valid OTP"
        })
    }
    const cache = await redisClient();
    const otpkey = `otp:${email}:${otp}`;
    
    if(!(await cache.get(otpkey))) {
        return res.status(400).json({
            message: "OTP expired, Please try again"
        })
    }

    await cache.del(otpkey)
    const user = await User.findOne({email}).select("-password")
    const tokenData = await generateTokens(user?._id, res)
    
    return res.status(200).json({
        message: "Logged In Successfully",
        user
    })
});

const getProfile = TryCatch(async(req, res) => {
    return res.status(200).json({
        message: `Welcome, ${req?.user?.name}`,
        user: req?.user
    })
})

const getRefreshToken = TryCatch( async (req, res) => {
    const refreshToken = req.cookies.refreshToken;
    if(!refreshToken) {
        return res.status(403).json({
            message: 'Please login - No token'
        })
    }
    const decoded = await verifyRefreshToken(refreshToken);
    if(!decoded) {
          return res.status(403).json({
            message: 'Invalid refresh token'
        })
    }
    await generateAccessToken(decoded?._id, res)

    return res.status(200).json({
        message: 'Token refreshed'
    })
})

const logoutUser = TryCatch( async (req,res) => {
    const user = req.user;
    const cache = await redisClient();
    await cache.del(`refresh-token:${user._id}`);
    // If cachedUser is null, skip deleting login-rate-limit
    const cachedUser = await cache.get(`user:${user._id}`);
    if (cachedUser) {
        try {
            const email = JSON.parse(cachedUser).email;
            await cache.del(`login-rate-limit:${req.ip}:${email}`);
            await cache.del(`user:${user._id}`);
        } catch (e) {
            // ignore JSON parse error
        }
    }
    res.clearCookie('accessToken');
    res.clearCookie('refreshToken');
    if (!res.headersSent) {
        return res.status(200).json({
            message: 'Logged out successfully'
        });
    }
})



module.exports = {registerUser, verifyUser, loginUser, verifyOtp, getProfile, getRefreshToken,logoutUser}