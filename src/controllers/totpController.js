import speakeasy from 'speakeasy'
import QRCode from 'qrcode'
import { db } from '../config/db.js'

// Generar secreto TOTP
export const generateTOTPSecret = async (req, res) => {
  try {
    const userId = req.user.id // Asumiendo que tienes middleware de autenticación (si tengo)

    const secret = speakeasy.generateSecret({
      name: `Cliente web 1 (${req.user.email})`, //aqui es el nombre de cliente? de Google Auth Platform/clientes
      issuer: "Sistema de Seguridad"
    })

    // Guardar secreto en la base de datos (temporalmente)
    await db.query(
      "UPDATE users SET totp_secret = ?, totp_enabled = false WHERE id_usuario = ?",
      [secret.base32, userId]
    )

    // Generar QR code
    const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url)

    res.json({
      success: true,
      secret: secret.base32,
      qrCode: qrCodeUrl,
      manualEntryCode: secret.otpauth_url
    })
  } catch (error) {
    console.error('Error generando TOTP:', error)
    res.status(500).json({ success: false, message: 'Error generando TOTP' })
  }
}

// Verificar código TOTP
export const verifyTOTP = async (req, res) => {
  try {
    const { token } = req.body
    const userId = req.user.id

    // Obtener secreto del usuario
    const [rows] = await db.query(
      "SELECT totp_secret FROM users WHERE id_usuario = ?",
      [userId]
    )

    if (rows.length === 0 || !rows[0].totp_secret) {
      return res.status(400).json({ success: false, message: 'TOTP no configurado' })
    }

    const verified = speakeasy.totp.verify({
      secret: rows[0].totp_secret,
      encoding: 'base32',
      token: token,
      window: 1 // Permite 30 segundos de margen
    })

    if (verified) {
      // Activar TOTP para el usuario
      await db.query(
        "UPDATE users SET totp_enabled = true WHERE id_usuario = ?",
        [userId]
      )

      res.json({ 
        success: true, 
        message: 'TOTP verificado y activado exitosamente' 
      })
    } else {
      res.status(400).json({ 
        success: false, 
        message: 'Código TOTP inválido' 
      })
    }
  } catch (error) {
    console.error('Error verificando TOTP:', error)
    res.status(500).json({ success: false, message: 'Error verificando TOTP' })
  }
}

// Validar código TOTP durante login
export const validateTOTPLogin = async (req, res) => {
  try {
    const { email, token } = req.body

    // Buscar usuario
    const [rows] = await db.query(
      "SELECT * FROM users WHERE email = ? AND totp_enabled = true",
      [email]
    )

    if (rows.length === 0) {
      return res.status(400).json({ 
        success: false, 
        message: 'Usuario no encontrado o TOTP no habilitado' 
      })
    }

    const user = rows[0]
    const verified = speakeasy.totp.verify({
      secret: user.totp_secret,
      encoding: 'base32',
      token: token,
      window: 1
    })

    if (verified) {
      res.json({ 
        success: true, 
        message: 'TOTP verificado exitosamente' 
      })
    } else {
      res.status(400).json({ 
        success: false, 
        message: 'Código TOTP inválido' 
      })
    }
  } catch (error) {
    console.error('Error validando TOTP:', error)
    res.status(500).json({ success: false, message: 'Error validando TOTP' })
  }
}

// Desactivar TOTP
export const disableTOTP = async (req, res) => {
  try {
    const userId = req.user.id

    await db.query(
      "UPDATE users SET totp_secret = NULL, totp_enabled = false WHERE id_usuario = ?",
      [userId]
    )

    res.json({ 
      success: true, 
      message: 'TOTP desactivado exitosamente' 
    })
  } catch (error) {
    console.error('Error desactivando TOTP:', error)
    res.status(500).json({ success: false, message: 'Error desactivando TOTP' })
  }
}