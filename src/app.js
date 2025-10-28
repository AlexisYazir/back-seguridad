import express from 'express'
import cors from 'cors'
import cookieParser from 'cookie-parser'
import session from 'express-session'
import passport from './config/passport.js'
import authRoutes from './routes/authRoutes.js'
import totpRoutes from './routes/totpRoutes.js'
import passwordResetRoutes from './routes/passwordReset.js';

const app = express()

app.use(cors({ 
  origin: 'https://sitio-seguridad.netlify.app', 
  credentials: true 
}))
app.use(express.json())
app.use(cookieParser())
app.use(session({
  secret: process.env.SESSION_SECRET || 'session_secret',
  resave: false,
  saveUninitialized: false
}))
app.use(express.json())
app.use(passport.initialize())
app.use(passport.session())

app.use('/api/auth', authRoutes)
app.use('/api/totp', totpRoutes)
app.use('/api/auth/password-reset', passwordResetRoutes);

app.get('/health', (req, res) => {
  res.json({ 
    status: 'OK',
    environment: process.env.NODE_ENV || 'development',
    timestamp: new Date().toISOString()
  })
})

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