import express from "express";
import { 
  register, 
  login,
  verify, 
  logout,
  verifyEmail,
  googleAuth, 
  googleCallback
} from "../controllers/authController.js";

const router = express.Router();

// Rutas
router.post("/register", register);
router.post("/login", login);
router.get("/verify", verify);
router.post("/logout", logout);
router.get("/verify-email", verifyEmail); 
router.get('/google', googleAuth)
router.get('/google/callback', googleCallback)

export default router;