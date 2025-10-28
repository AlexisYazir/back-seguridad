import express from 'express';
import {
  sendSMS,
  userVerifyUserEmail,
  verifyTokenSms,
  verifyTokenEmail,
    resetPsw,
} from '../controllers/passwordResetController.js';
import {sendEmail} from '../controllers/emailController.js';

const router = express.Router();

// consulta de usuario
router.post('/send-sms', sendSMS);
router.post('/send-email', sendEmail);
router.post('/verify-user-email', userVerifyUserEmail);
router.post('/verify-token-sms', verifyTokenSms);
router.post('/verify-token-email', verifyTokenEmail);
router.post('/reset-psw', resetPsw);

export default router;