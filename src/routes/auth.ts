import { Router } from "express";
import { forgotPassword, resetPassword, signin, signup, verifyEmail, protectedRoute,  refreshToken, 
  logout, 
  logoutAllDevices, } from "../controllers/auth";
import tokenCheck from "../middlewares/authMiddleware";

const authRoutes = Router();

authRoutes.post("/signup", signup);
authRoutes.post("/signin", signin);
authRoutes.post('/refresh-token', refreshToken);
authRoutes.post('/logout', logout);
authRoutes.post('/logout-all', tokenCheck, logoutAllDevices);
authRoutes.post('/forgot-password', forgotPassword);
authRoutes.post('/reset-password', resetPassword);
authRoutes.post('/verify-email', verifyEmail);

authRoutes.post("/protected", tokenCheck, protectedRoute)

export default authRoutes;