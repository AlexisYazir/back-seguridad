import { db } from "../config/db.js";
import twilio from "twilio";
import dotenv from "dotenv";
import bcrypt from "bcrypt";
dotenv.config();

const accountSid = process.env.TWILIO_ACCOUNT_SID;
const authToken = process.env.TWILIO_AUTH_TOKEN;
const twilioPhone = process.env.TWILIO_PHONE_NUMBER;
const client = twilio(accountSid, authToken);

// Normalizar y preparar el número para Twilio
const formatPhoneNumber = (phone) => {
  if (!phone) return null;

  // Eliminar todo excepto números
  let cleaned = phone.toString().replace(/\D/g, '');

  // Si empieza con 52 y tiene 12 dígitos, ya está bien
  if (cleaned.startsWith('52') && cleaned.length === 12) {
    return `+${cleaned}`;
  }
  // Si tiene 10 dígitos, agregar el +52
  if (cleaned.length === 10) {
    return `+52${cleaned}`;
  }
  // Si no, lo regresamos con un + por si acaso
  return `+${cleaned}`;
};

//  envio de SMS a usuario
export const sendSMS = async (req, res) => {
  try {
    const { telefono } = req.body;
    const formattedPhone = formatPhoneNumber(telefono);
    const code = Math.floor(100000 + Math.random() * 900000);
    console.log("Número formateado:", formattedPhone);

    await db.query(
      "UPDATE users set token= ? where telefono= ?",
      [code, telefono]
    );

    // Enviar SMS
    await client.messages.create({
      body: `Tu código de verificación es: ${code}`,
      from: twilioPhone,
      to: formattedPhone,
    });

    res.status(200).json({
      success: true,
      message: "Código enviado correctamente al número registrado"
    }); 

  } catch (error) {
    console.error("Error en verificación de usuario:", error);
    res.status(500).json({
      success: false,
      message: "Error interno al verificar usuario o enviar el código"
    });
  }
};

export const userVerifyUserEmail = async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({
        success: false,
        message: "El correo es requerido"
      });
    }
    // Buscar usuario en la base de datos
    const [user] = await db.query(
      "SELECT id_usuario, telefono, email FROM users WHERE email = ?",
      [email]
    );

    if (user.length === 0) {
      return res.status(404).json({
        success: false,
        message: "No existe una cuenta con este correo para recuperar la contraseña BACKEND OK"
      });
    }

    console.log(user);
    return res.status(200).json({
      success: true,
      message: "Datos de usuario encontrados, puedes proceder",
      datos: user[0]
    });


  } catch (error) {
    console.error("Error en verificación de usuario:", error);
    res.status(500).json({
      success: false,
      message: "Error interno al verificar usuario"
    });
  }
};

export const verifyTokenSms = async (req, res) => {
  try {
    const { telefono, token } = req.body;

    if (!telefono) {
      return res.status(400).json({ success: false, message: "El teléfono es requerido" });
    }
    if (!token) {
      return res.status(400).json({ success: false, message: "El token es requerido" });
    }

    const [user] = await db.query(
      "SELECT id_usuario FROM users WHERE telefono = ? AND token = ?",
      [telefono, token]
    );

    if (user.length === 0) {
      return res.status(404).json({
        success: false,
        message: "El código introducido es incorrecto"
      });
    }

    console.log(user);

    return res.status(200).json({
      success: true,
      message: "Código correcto, puedes proceder con la recuperación de contraseña",
      datos: user[0]
    });

  } catch (error) {
    console.error("Error en verificación de código:", error);
    res.status(500).json({
      success: false,
      message: "Error interno al verificar usuario"
    });
  }
};
export const verifyTokenEmail = async (req, res) => {
  try {
    const { id, token } = req.body;

    if (!id) {
      return res.status(400).json({ success: false, message: "El id usuario es requerido" });
    }
    if (!token) {
      return res.status(400).json({ success: false, message: "El token es requerido" });
    }

    const [user] = await db.query(
      "SELECT id_usuario, telefono FROM users WHERE id_usuario = ? AND token = ?",
      [id, token]
    );

    if (user.length === 0) {
      return res.status(404).json({
        success: false,
        message: "El código introducido es incorrecto tkn"
      });
    }

    console.log(user);

    return res.status(200).json({
      success: true,
      message: "Código correcto, puedes proceder con la recuperación de contraseña",
      datos: user[0]
    });

  } catch (error) {
    console.error("Error en verificación de código:", error);
    res.status(500).json({
      success: false,
      message: "Error interno al verificar usuario"
    });
  }
};

export const resetPsw = async (req, res) => {
  try {
    const { telefono,psw } = req.body;
     if (!telefono) {
      return res.status(400).json({ success: false, message: "El teléfono es requerido" });
    }
    if (!psw) {
      return res.status(400).json({ success: false, message: "La contraseña es requerido" });
    }
     // Verifica si el telefono ya existe
    const [rows] = await db.query("SELECT * FROM users WHERE telefono = ?", [telefono]);
    if (rows.length <= 0) {
      return res.status(409).json({ message: "El telefono NO existe" });
    }
    const hashedPassword = await bcrypt.hash(psw, 10);

    await db.query(
      "UPDATE users set pasw= ? where telefono= ?",
      [hashedPassword, telefono]
    );

    res.status(200).json({
      success: true,
      message: "Contraseña actualizada correctamente"
    }); 

  } catch (error) {
    console.error("Error en actualizacion de contraseña:", error);
    res.status(500).json({
      success: false,
      message: "Error interno al actualizar la contraseña"
    });
  }
};