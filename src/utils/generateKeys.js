const crypto = require('crypto');

const generateOTP = () => {
  return crypto.randomInt(100000, 999999); 
}

const generateVerifyToken = () => {
  return crypto.randomBytes(32).toString("hex");
}

module.exports = {generateOTP, generateVerifyToken}