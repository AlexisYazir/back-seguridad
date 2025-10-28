import mysql from "mysql2/promise";
import dotenv from "dotenv";
dotenv.config();

export const db = await mysql.createConnection({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT, // ✅ Agregar puerto
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  ssl: {
    rejectUnauthorized: false // ✅ SSL requerido por Railway
  }
});

console.log("Conectado a Railway ✅");