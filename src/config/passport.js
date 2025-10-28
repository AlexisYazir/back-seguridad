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
      console.log('🔐 Procesando autenticación Google para:', profile.emails[0].value);
      
      const googleEmail = profile.emails[0].value;
      const googleId = profile.id;
      const displayName = profile.displayName || googleEmail.split('@')[0];

      // 1. PRIMERO buscar solo por google_id (usuarios que ya se registraron con Google)
      const [usersByGoogleId] = await db.query(
        "SELECT * FROM users WHERE google_id = ?", 
        [googleId]
      );

      if (usersByGoogleId.length > 0) {
        console.log('✅ Usuario encontrado por Google ID:', usersByGoogleId[0].email);
        return done(null, usersByGoogleId[0]);
      }

      // 2. BUSCAR por email (usuarios existentes que quieren usar Google)
      const [usersByEmail] = await db.query(
        "SELECT * FROM users WHERE email = ?", 
        [googleEmail]
      );

      if (usersByEmail.length > 0) {
        console.log('✅ Usuario encontrado por email, actualizando Google ID...');
        
        // Actualizar el usuario existente con el Google ID
        await db.query(
          "UPDATE users SET google_id = ?, email_verified = true WHERE email = ?",
          [googleId, googleEmail]
        );
        
        // Obtener el usuario actualizado
        const [updatedUser] = await db.query(
          "SELECT * FROM users WHERE email = ?", 
          [googleEmail]
        );
        
        return done(null, updatedUser[0]);
      }

      // 3. CREAR NUEVO USUARIO (si no existe por Google ID ni por email)
      console.log('🆕 Creando nuevo usuario con Google...');
      
      // Generar username único
      let username = displayName;
      let counter = 1;
      
      // Verificar si el username ya existe
      let [existingUsername] = await db.query(
        "SELECT id_usuario FROM users WHERE username = ?", 
        [username]
      );
      
      while (existingUsername.length > 0) {
        username = `${displayName}${counter}`;
        [existingUsername] = await db.query(
          "SELECT id_usuario FROM users WHERE username = ?", 
          [username]
        );
        counter++;
      }

      // Insertar nuevo usuario
      const [result] = await db.query(
        `INSERT INTO users 
         (username, email, google_id, email_verified, created_at) 
         VALUES (?, ?, ?, true, NOW())`,
        [username, googleEmail, googleId]
      );

      const newUser = {
        id_usuario: result.insertId,
        username: username,
        email: googleEmail,
        google_id: googleId,
        email_verified: true
      };

      console.log('✅ Nuevo usuario creado exitosamente:', newUser.email);
      return done(null, newUser);

    } catch (error) {
      console.error('❌ Error en Google Strategy:', error);
      
      // Manejo específico de errores de duplicación
      if (error.code === 'ER_DUP_ENTRY') {
        if (error.sqlMessage.includes('email')) {
          console.log('⚠️ Email duplicado, intentando recuperar usuario...');
          // Intentar recuperar el usuario existente
          try {
            const [existingUser] = await db.query(
              "SELECT * FROM users WHERE email = ?", 
              [profile.emails[0].value]
            );
            if (existingUser.length > 0) {
              console.log('✅ Usuario recuperado después de error de duplicación');
              return done(null, existingUser[0]);
            }
          } catch (recoveryError) {
            console.error('Error recuperando usuario:', recoveryError);
          }
        }
      }
      
      return done(error, null);
    }
  }
));

// Serialización del usuario
passport.serializeUser((user, done) => {
  done(null, user.id_usuario);
});

passport.deserializeUser(async (id, done) => {
  try {
    const [rows] = await db.query(
      "SELECT id_usuario, username, email, google_id, email_verified FROM users WHERE id_usuario = ?", 
      [id]
    );
    done(null, rows[0]);
  } catch (error) {
    done(error, null);
  }
});

export default passport;