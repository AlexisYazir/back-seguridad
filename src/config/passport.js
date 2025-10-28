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
      console.log('🔐 Google OAuth para:', profile.emails[0].value);
      
      // Buscar usuario por Google ID PRIMERO
      const [usersByGoogleId] = await db.query(
        "SELECT * FROM users WHERE google_id = ?", 
        [profile.id]
      );

      if (usersByGoogleId.length > 0) {
        console.log('✅ Usuario encontrado por Google ID:', usersByGoogleId[0].email);
        return done(null, usersByGoogleId[0]);
      }

      // Buscar por email
      const [usersByEmail] = await db.query(
        "SELECT * FROM users WHERE email = ?", 
        [profile.emails[0].value]
      );

      if (usersByEmail.length > 0) {
        console.log('✅ Usuario encontrado por email:', usersByEmail[0].email);
        
        // Actualizar con Google ID
        await db.query(
          "UPDATE users SET google_id = ? WHERE id_usuario = ?",
          [profile.id, usersByEmail[0].id_usuario]
        );
        
        usersByEmail[0].google_id = profile.id;
        return done(null, usersByEmail[0]);
      }

      // Crear nuevo usuario
      console.log('🆕 Creando nuevo usuario:', profile.emails[0].value);
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

      console.log('✅ Nuevo usuario creado:', newUser.email);
      return done(null, newUser);

    } catch (error) {
      console.error('❌ Error en Google Strategy:', error);
      return done(error, null);
    }
  }
))

// ⚠️ ELIMINAR serializeUser y deserializeUser si solo usas JWT
// O mantenerlos vacíos si necesitas la estructura

passport.serializeUser((user, done) => {
  done(null, user); // Solo pasar el usuario, no el ID
});

passport.deserializeUser((user, done) => {
  done(null, user); // Devolver el mismo usuario
});

export default passport