const { registerUser, loginUser, verifyOtp, getProfile, getRefreshToken, logoutUser } = require('../controller/UserController');
const { isAuthenticated } = require('../middleware/isAuth');
const router = require('express').Router();

router.post('/register', registerUser);
router.post('/login', loginUser);
router.post('/verify-otp', verifyOtp);
router.get('/profile', isAuthenticated, getProfile)
router.get('/refresh-token', getRefreshToken)
router.get('/logout',isAuthenticated, logoutUser)




module.exports = router