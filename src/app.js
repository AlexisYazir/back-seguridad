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
  origin: 'http://localhost:5173', 
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

export default app