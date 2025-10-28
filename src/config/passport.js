import passport from 'passport'
import { Strategy as GoogleStrategy } from 'passport-google-oauth20'
import { db } from './db.js'
import dotenv from 'dotenv'
dotenv.config()


passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "https://back-seguridad-ruby.vercel.app/api/auth/google/callback"
  },
  async (accessToken, refreshToken, profile, done) => {
    try {
      // Buscar usuario por Google ID
      const [existingUser] = await db.query(
        "SELECT * FROM users WHERE google_id = ? OR email = ?", 
        [profile.id, profile.emails[0].value]
      )

      if (existingUser.length > 0) {
        // Actualizar usuario existente con Google ID si es necesario
        if (!existingUser[0].google_id) {
          await db.query(
            "UPDATE users SET google_id = ? WHERE id_usuario = ?",
            [profile.id, existingUser[0].id_usuario]
          )
        }
        return done(null, existingUser[0])
      }

      // Crear nuevo usuario
      const [result] = await db.query(
        `INSERT INTO users 
         (username, email, google_id, email_verified, created_at) 
         VALUES (?, ?, ?, true, NOW())`,
        [
          profile.displayName || profile.emails[0].value.split('@')[0],
          profile.emails[0].value,
          profile.id
        ]
      )

      const newUser = {
        id_usuario: result.insertId,
        username: profile.displayName || profile.emails[0].value.split('@')[0],
        email: profile.emails[0].value,
        google_id: profile.id,
        email_verified: true
      }

      return done(null, newUser)
    } catch (error) {
      return done(error, null)
    }
  }
))

// Serialización del usuario
passport.serializeUser((user, done) => {
  done(null, user.id_usuario)
})

passport.deserializeUser(async (id, done) => {
  try {
    const [rows] = await db.query("SELECT * FROM users WHERE id_usuario = ?", [id])
    done(null, rows[0])
  } catch (error) {
    done(error, null)
  }
})

export default passport