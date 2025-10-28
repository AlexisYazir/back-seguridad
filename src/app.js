import express from 'express'
import cors from 'cors'
import cookieParser from 'cookie-parser'
import session from 'express-session'
import passport from './config/passport.js'
import authRoutes from './routes/authRoutes.js'
import totpRoutes from './routes/totpRoutes.js'
import passwordResetRoutes from './routes/passwordReset.js'

const app = express()

// ✅ CONFIGURACIÓN CORS MEJORADA
app.use(cors({ 
  origin: [
    'https://sitio-seguridad.netlify.app',
    'http://localhost:5173' // Para desarrollo
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Cookie', 'Set-Cookie'],
  exposedHeaders: ['Set-Cookie']
}))

app.use(express.json())
app.use(cookieParser())

// ✅ CONFIGURACIÓN DE SESSION MEJORADA
app.use(session({
  secret: process.env.SESSION_SECRET || 'session_secret_production',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: true, // ✅ Solo HTTPS en producción
    httpOnly: true, // ✅ Prevenir acceso via JavaScript
    sameSite: 'none', // ✅ Permitir cross-domain
    maxAge: 24 * 60 * 60 * 1000, // 24 horas
    domain: '.vercel.app' // ✅ O el dominio de tu backend
  }
}))

app.use(passport.initialize())
app.use(passport.session())

// Rutas
app.use('/api/auth', authRoutes)
app.use('/api/totp', totpRoutes)
app.use('/api/auth/password-reset', passwordResetRoutes)

// Health check (solo uno, quita el duplicado)
app.get('/health', (req, res) => {
  res.json({ 
    status: 'OK',
    environment: process.env.NODE_ENV || 'development',
    timestamp: new Date().toISOString()
  })
})

app.get('/', (req, res) => {
  res.json({ 
    message: 'Backend de Seguridad API',
    version: '1.0.0',
    environment: process.env.NODE_ENV || 'development'
  })
})

export default app