import express from 'express'
import { 
  generateTOTPSecret, 
  verifyTOTP, 
  validateTOTPLogin, 
  disableTOTP 
} from '../controllers/totpController.js'
import { authenticateToken } from '../middleware/authMiddleware.js'

const router = express.Router()

router.get('/setup', authenticateToken, generateTOTPSecret)
router.post('/verify', authenticateToken, verifyTOTP)
router.post('/validate-login', validateTOTPLogin)
router.post('/disable', authenticateToken, disableTOTP)

export default router