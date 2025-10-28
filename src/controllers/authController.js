import { db } from "../config/db.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import { sendVerificationEmail } from './emailController.js'
import passport from '../config/passport.js'
dotenv.config();

// 🔧 CONFIGURACIÓN UNIFICADA DE COOKIES
const cookieConfig = {
  httpOnly: true,
  secure: true, // ✅ SIEMPRE true en producción
  sameSite: 'none', // ✅ SIEMPRE none para cross-domain
  maxAge: 24 * 60 * 60 * 1000, // 24 horas
  domain: '.vercel.app' // ✅ SIEMPRE el mismo dominio
};

// 🔧 CONFIGURACIÓN UNIFICADA PARA LIMPIAR COOKIES
const clearCookieConfig = {
  httpOnly: true,
  secure: true,
  sameSite: 'none',
  domain: '.vercel.app'
};

export const register = async (req, res) => {
  try {
    const { username, email, password, telefono } = req.body;

    // Verifica campos obligatorios
    if (!email || !password || !username || !telefono) {
      return res.status(400).json({ message: "Faltan datos" });
    }

    // Verifica si el usuario ya existe
    const [rows_u] = await db.query("SELECT * FROM users WHERE username = ?", [username]);
    if (rows_u.length > 0) {
      return res.status(409).json({ message: "El usuario ya existe" });
    }

    // Verifica si el correo ya existe
    const [rows] = await db.query("SELECT * FROM users WHERE email = ?", [email]);
    if (rows.length > 0) {
      return res.status(409).json({ message: "El correo ya existe" });
    }

    // Verifica si el telefono ya existe
    const [rows_t] = await db.query("SELECT * FROM users WHERE telefono = ?", [telefono]);
    if (rows_t.length > 0) {
      return res.status(409).json({ message: "El telefono ya esta en uso" });
    }

    // Hashea la contraseña
    const hashedPassword = await bcrypt.hash(password, 10);

    // Generar token de verificación
    const verificationToken = jwt.sign(
      { email, username },
      process.env.JWT_SECRET || 'mi_secret',
      { expiresIn: '24h' }
    );

    //  PRIMERO intentar enviar el correo
    const emailResult = await sendVerificationEmail(email, username, verificationToken);

    if (!emailResult.success) {
      console.error('Error enviando email:', emailResult.error);
      
      // Mensajes específicos según el tipo de error
      if (emailResult.errorType === 'invalid_email') {
        return res.status(400).json({ 
          message: "El correo electrónico no existe o no es válido. Por favor verifica tu dirección de email." 
        });
      } else if (emailResult.errorType === 'email_credentials') {
        return res.status(500).json({ 
          message: "Error de configuración del servidor de email. Contacta al administrador." 
        });
      } else {
        return res.status(500).json({ 
          message: "Error al enviar el correo de verificación. Por favor intenta nuevamente." 
        });
      }
    }
    // Luego, insertar el usuario en la base de datos
    await db.query(
      "INSERT INTO users (username, email, pasw, telefono, email_verified, verification_token, created_at) VALUES (?, ?, ?, ?, ?, ?, NOW())",
      [username, email, hashedPassword, telefono, false, verificationToken]
    );

    res.status(201).json({ 
      message: "Operación exitosa. Por favor verifica tu bandeja de entrada para confirmar tu cuenta.",
      emailSent: true
    });

  } catch (error) {
    console.error("Error en register:", error);
    res.status(500).json({ message: "Error en el servidor" });
  }
};

// login
export const login = async (req, res) => {
  try {
    const { email, password } = req.body

    if (!email || !password) {
      return res.status(400).json({ message: 'Faltan datos' })
    }

    const [rows] = await db.query('SELECT * FROM users WHERE email = ?', [email])
    if (rows.length === 0) {
      return res.status(404).json({ message: 'Usuario no encontrado' })
    }

    const [verifi] = await db.query('SELECT * FROM users WHERE email = ? and email_verified =1', [email])
    if (verifi.length === 0) {
      return res.status(404).json({ message: 'Su cuenta no esta activada, verifique su correo e intente de nuevo' })
    }

    const user = rows[0]
    const match = await bcrypt.compare(password, user.pasw)
    if (!match) {
      return res.status(401).json({ message: 'Contraseña incorrecta' })
    }

    // Crear JWT con más datos del usuario
    const token = jwt.sign(
      { 
        id: user.id_usuario, 
        email: user.email,
        username: user.username,
        telefono: user.telefono
      },
      process.env.JWT_SECRET || 'mi_secret', 
      { expiresIn: '24h' }
    )

    // ✅ CONFIGURACIÓN UNIFICADA
    res.cookie('token', token, cookieConfig)

    //  Enviar también los datos del usuario en la respuesta
    res.json({ 
      message: 'Login exitoso', 
      user: {
        id: user.id_usuario,
        email: user.email,
        username: user.username,
        telefono: user.telefono,
      }
    })
  } catch (error) {
    console.error('Error en login back:', error)
    res.status(500).json({ message: 'Error en el servidor' })
  }
}

export const verify = async (req, res) => {
  try {
    const token = req.cookies.token
    console.log('🔐 Verificando autenticación - Token presente:', !!token)
    
    if (!token) {
      console.log('❌ No hay token en cookies')
      return res.status(401).json({ message: 'No autenticado' })
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'mi_secret')
    console.log('✅ Token válido para usuario ID:', decoded.id)
    
    // Buscar usuario sin la contraseña
    const [rows] = await db.query(
      'SELECT id_usuario, email, username FROM users WHERE id_usuario = ?', 
      [decoded.id]
    )

    if (rows.length === 0) {
      console.log('❌ Usuario no encontrado en BD para ID:', decoded.id)
      return res.status(404).json({ message: 'Usuario no encontrado' })
    }

    console.log('✅ Usuario verificado:', rows[0].email)
    res.json({ user: rows[0] })
    
  } catch (err) {
    console.error('❌ Error en verify:', err.message)
    
    // ✅ CONFIGURACIÓN UNIFICADA
    res.clearCookie('token', clearCookieConfig)
    
    res.status(401).json({ message: 'Token inválido o expiró' })
  }
}

export const logout = (req, res) => {
  try {
    // ✅ CONFIGURACIÓN UNIFICADA
    res.clearCookie('token', clearCookieConfig)

    res.json({ 
      success: true, 
      message: 'Sesión cerrada exitosamente' 
    })
  } catch (error) {
    console.error('Error en logout:', error)
    res.status(500).json({ 
      success: false, 
      message: 'Error al cerrar sesión' 
    })
  }
}

export const verifyEmail = async (req, res) => {
  try {
    const { token } = req.query;

    if (!token) {
      return res.status(400).json({ message: "Token de verificación requerido" });
    }

    // Verificar el token
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'mi_secret');
    
    // Buscar usuario por el token
    const [rows] = await db.query(
      "SELECT * FROM users WHERE verification_token = ? AND email = ?",
      [token, decoded.email]
    );

    if (rows.length === 0) {
      return res.status(404).json({ message: "Token inválido o usuario no encontrado" });
    }

    const user = rows[0];

    // Verificar si el email ya estaba verificado
    if (user.email_verified) {
      return res.status(400).json({ message: "El email ya fue verificado anteriormente" });
    }

    // Actualizar usuario como verificado y limpiar el token
    await db.query(
      "UPDATE users SET email_verified = true, verification_token = NULL WHERE id_usuario = ?",
      [user.id_usuario]
    );

    // Redirigir a una página de éxito o mostrar mensaje
    res.send(`
      <html>
        <head>
          <title>Email Verificado</title>
          <style>
            body { font-family: Arial, sans-serif; text-align: center; padding: 50px; background-color: #0d0d0d; color: #42b983; }
            .success { background-color: white; padding: 40px; border-radius: 10px; max-width: 500px; margin: 0 auto; }
            .btn { background-color: #42b983; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; display: inline-block; margin-top: 20px; }
          </style>
        </head>
        <body>
          <div class="success">
            <h1>✅ Email Verificado Exitosamente</h1>
            <p>Tu cuenta ha sido verificada. Ahora puedes iniciar sesión.</p>
            <a href="https://sitio-seguridad.netlify.app/login" class="btn">Ir al Login</a>
          </div>
        </body>
      </html>
    `);

  } catch (error) {
    console.error("Error en verifyEmail:", error);
    
    if (error.name === 'TokenExpiredError') {
      return res.status(400).json({ message: "El token de verificación ha expirado" });
    }
    
    if (error.name === 'JsonWebTokenError') {
      return res.status(400).json({ message: "Token de verificación inválido" });
    }

    res.status(500).json({ message: "Error en el servidor" });
  }
};

//para google login oauth
export const googleAuth = passport.authenticate('google', {
  scope: ['profile', 'email']
})

export const googleCallback = (req, res, next) => {
  passport.authenticate('google', { session: false }, (err, user, info) => {
    console.log('--- CALLBACK DE GOOGLE ---')
    console.log('Usuario recibido:', user ? user.email : 'NO USER')
    console.log('---------------------------')

    if (err) {
      console.error('Error en autenticación con Google:', err)
      return res.redirect('https://sitio-seguridad.netlify.app/login?error=auth_failed')
    }
    if (!user) {
      console.error('Usuario no encontrado después de autenticación con Google')
      return res.redirect('https://sitio-seguridad.netlify.app/login?error=user_not_found')
    }

    // Crear token JWT
    const token = jwt.sign(
      { 
        id: user.id_usuario, 
        email: user.email,
        username: user.username 
      },
      process.env.JWT_SECRET || 'mi_secret',
      { expiresIn: '24h' }
    )

    // ✅ CONFIGURACIÓN UNIFICADA
    res.cookie('token', token, cookieConfig)

    console.log('✅ Cookie establecida para:', user.email)
    res.redirect('https://sitio-seguridad.netlify.app/dashboard')
  })(req, res, next)
}

// 🔍 ENDPOINT TEMPORAL PARA DEBUG
export const debugAuth = async (req, res) => {
  const token = req.cookies.token;
  console.log('🔍 DEBUG AUTH - Token presente:', !!token);
  
  if (token) {
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET || 'mi_secret');
      console.log('🔍 DEBUG AUTH - Token válido para:', decoded.email);
      
      const [user] = await db.query('SELECT * FROM users WHERE id_usuario = ?', [decoded.id]);
      console.log('🔍 DEBUG AUTH - Usuario en BD:', user[0]?.email);
      
      res.json({ 
        tokenPresent: true, 
        tokenValid: true,
        user: user[0] ? { id: user[0].id_usuario, email: user[0].email } : null,
        decoded 
      });
    } catch (error) {
      console.log('🔍 DEBUG AUTH - Token inválido:', error.message);
      res.json({ tokenPresent: true, tokenValid: false, error: error.message });
    }
  } else {
    res.json({ tokenPresent: false, tokenValid: false });
  }
};