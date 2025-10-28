import twilio from 'twilio';
import dotenv from 'dotenv';

dotenv.config();

const client = twilio(
  process.env.TWILIO_ACCOUNT_SID,
  process.env.TWILIO_AUTH_TOKEN
);

/**
 * Envía un código de verificación por SMS
 * @param {string} telefono - Número de teléfono (formato: +521234567890)
 * @param {string} codigo - Código de 6 dígitos
 * @returns {Object} Resultado del envío
 */
export const sendVerificationSMS = async (telefono, codigo) => {
  try {
    // En desarrollo, simular envío si no hay credenciales de Twilio
    if (!process.env.TWILIO_ACCOUNT_SID || process.env.TWILIO_ACCOUNT_SID === 'your_account_sid_here') {
      console.log(`🚨 MODO DESARROLLO: Código SMS para ${telefono}: ${codigo}`);
      return { 
        success: true, 
        sid: 'dev_mode',
        message: 'SMS simulado en desarrollo' 
      };
    }

    const message = await client.messages.create({
      body: `🔐 Tu código de recuperación es: ${codigo}. Válido por 10 minutos.`,
      from: process.env.TWILIO_PHONE_NUMBER,
      to: telefono
    });

    console.log(`✅ SMS enviado a ${telefono}, SID: ${message.sid}`);
    return { 
      success: true, 
      sid: message.sid,
      message: 'SMS enviado correctamente' 
    };

  } catch (error) {
    console.error('❌ Error enviando SMS:', error.message);
    
    // Manejo específico de errores de Twilio
    if (error.code === 21211) {
      return { 
        success: false, 
        error: 'El número de teléfono no es válido',
        errorType: 'invalid_number' 
      };
    } else if (error.code === 21408) {
      return { 
        success: false, 
        error: 'No tien permisos para enviar SMS a este número',
        errorType: 'permission_denied' 
      };
    } else if (error.code === 21610) {
      return { 
        success: false, 
        error: 'El número no puede recibir SMS',
        errorType: 'sms_not_supported' 
      };
    }

    return { 
      success: false, 
      error: error.message,
      errorType: 'twilio_error' 
    };
  }
};

/**
 * Genera un código de 6 dígitos
 */
export const generateVerificationCode = () => {
  return Math.floor(100000 + Math.random() * 900000).toString();
};