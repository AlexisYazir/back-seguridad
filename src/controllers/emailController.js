import nodemailer from 'nodemailer'
import jwt from 'jsonwebtoken'
import { db } from "../config/db.js";

// Configurar transporter
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
})

// Generar token de verificación
const generateVerificationToken = (email) => {
  return jwt.sign(
    { email },
    process.env.JWT_SECRET || 'mi_secret',
    { expiresIn: '24h' } // Token expira en 24 horas
  )
}

export const sendVerificationEmail = async (userEmail, username, verificationToken) => {
  try {
    const verificationLink = `https://back-seguridad-ruby.vercel.app/api/auth/verify-email?token=${verificationToken}`
    
    const mailOptions = {
      from: `"Sistema de Seguridad" <${process.env.EMAIL_USER}>`,
      to: userEmail,
      subject: 'Verifica tu cuenta - Sistema de Seguridad',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; background-color: #f9f9f9; padding: 20px; border-radius: 10px;">
          <div style="text-align: center; background-color: #0d0d0d; padding: 20px; border-radius: 10px 10px 0 0;">
            <h1 style="color: #42b983; margin: 0;">Sistema de Seguridad</h1>
          </div>
          <div style="background-color: white; padding: 30px; border-radius: 0 0 10px 10px;">
            <h2 style="color: #333;">¡Hola, ${username}!</h2>
            <p style="color: #666; font-size: 16px;">Gracias por registrarte en nuestro sistema. Para activar tu cuenta, por favor verifica tu dirección de email haciendo clic en el siguiente botón:</p>
            
            <div style="text-align: center; margin: 30px 0;">
              <a href="${verificationLink}" 
                 style="background-color: #42b983; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; font-weight: bold; display: inline-block;">
                Verificar Mi Cuenta
              </a>
            </div>
            
            <p style="color: #666; font-size: 14px;">Si el botón no funciona, copia y pega este enlace en tu navegador:</p>
            <p style="color: #42b983; font-size: 14px; word-break: break-all;">${verificationLink}</p>
            
            <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #eee;">
              <p style="color: #999; font-size: 12px;">Este enlace expirará en 24 horas.</p>
              <p style="color: #999; font-size: 12px;">Si no te registraste en nuestro sistema, por favor ignora este email.</p>
            </div>
          </div>
        </div>
      `
    }
// Verificar conexión primero
    await transporter.verify();

    const result = await transporter.sendMail(mailOptions);
    console.log('Email de verificación enviado a:', userEmail);
    return { success: true, messageId: result.messageId };
    
  } catch (error) {
    console.error('Error enviando email de verificación:', error);
    
    // Mejor detección de tipos de error
    let errorType = 'general';
    const errorMessage = error.message.toLowerCase();
    
    if (error.responseCode === 550 || 
        errorMessage.includes('550') ||
        errorMessage.includes('recipient') ||
        errorMessage.includes('not found') ||
        errorMessage.includes('invalid') ||
        errorMessage.includes('rejected') ||
        errorMessage.includes('does not exist') ||
        errorMessage.includes('no such user')) {
      errorType = 'invalid_email';
    } else if (errorMessage.includes('auth') || errorMessage.includes('credentials')) {
      errorType = 'email_credentials';
    }
    
    return { 
      success: false, 
      error: error.message,
      errorType: errorType
    };
  }
};

export const sendEmail = async (req, res) => {
  try {    
    const { email } = req.body;
    const code = Math.floor(100000 + Math.random() * 900000); // 6 dígitos
     await db.query(
          "UPDATE users set token= ? where email= ?",
          [code, email]
        );

    const mailOptions = {
      from: `"Sistema de Seguridad" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: 'Código de Verificación - Sistema de Seguridad',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; background-color: #f9f9f9; padding: 20px; border-radius: 10px;">
          <div style="text-align: center; background-color: #0d0d0d; padding: 20px; border-radius: 10px 10px 0 0;">
            <h1 style="color: #42b983; margin: 0;">Código de Seguridad</h1>
          </div>
          <div style="background-color: white; padding: 30px; border-radius: 0 0 10px 10px;">
            <h2 style="color: #333;">¡Hola, ${email}!</h2>
            <p style="color: #666; font-size: 16px;">Este es tu código para recuperar contraseña:</p>
            <p style="color: #666; font-size: 20px; font-weight: bold;">${code}</p>
            <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #eee;">
              <p style="color: #999; font-size: 12px;">Este código expirará en 24 horas.</p>
            </div>
          </div>
        </div>
      `
    };

    // Enviar email
    const result = await transporter.sendMail(mailOptions);
    console.log('Email de verificación enviado a:', email);

    return res.status(200).json({
      success: true,
      message: "Código enviado correctamente al número registrado"
    }); 

  } catch (error) {
    console.error('Error enviando email de código:', error);

    let errorType = 'general';
    const errorMessage = error.message.toLowerCase();

    if (error.responseCode === 550 ||
        errorMessage.includes('550') ||
        errorMessage.includes('recipient') ||
        errorMessage.includes('not found') ||
        errorMessage.includes('invalid') ||
        errorMessage.includes('rejected') ||
        errorMessage.includes('does not exist') ||
        errorMessage.includes('no such user')) {
      errorType = 'invalid_email';
    } else if (errorMessage.includes('auth') || errorMessage.includes('credentials')) {
      errorType = 'email_credentials';
    }

   console.error("Error en verificación de usuario:", error);
    res.status(500).json({
      success: false,
      message: "Error interno al verificar usuario o enviar el código"
    });
  }
};
