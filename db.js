const { Pool } = require("pg");
require("dotenv").config();

const pool = new Pool({
  user: `${process.env.DATABASE_USER}`,
  host: "localhost",
  database: `${process.env.DATABASE_NAME}`,
  password: `${process.env.DATABASE_USER_PASS}`,
  port: process.env.DATABASE_PORT,
});

module.exports = pool;
