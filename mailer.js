const nodemailer = require("nodemailer");
require("dotenv").config();

const transporter = nodemailer.createTransport({
  host: "mail.bazarigo.com",
  port: 465,
  secure: true,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.APP_PASSWORD,
  },
  logger: true,
  debug: true,
  tls: {
    rejectUnauthorized: false, // fixes common cPanel SSL issues
  },
});

module.exports = transporter;
