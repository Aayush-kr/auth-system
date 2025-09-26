const nodeMailer = require('nodemailer');



// Create a test account or replace with real credentials.
const transporter = nodeMailer.createTransport({
  host: "smtp.gmail.com",
  port: 465,
  secure: true, // true for 465, false for other ports
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASSWORD
  },
});

const sendMail = async (to, subject, text, html) => {
  console.log("process.env.SMTP_USER", process.env.SMTP_USER);
  console.log("process.env.SMTP_PASSWORD", process.env.SMTP_PASSWORD);
    const info = await transporter.sendMail({
    from: process.env.SMTP_USER,
    to,
    subject,
    text,
    html
  });
  console.log("Email sent:", info.messageId);
}


module.exports = {sendMail}
