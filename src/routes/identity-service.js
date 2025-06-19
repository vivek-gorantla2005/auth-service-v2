import express from "express";
import identityController from "../controllers/identity-controller.js";

const { registerUser, login , refresh_token,logout} = identityController;

const router = express.Router();

router.post('/register', registerUser);
router.post('/login', login);
router.post('/refresh_token',refresh_token);
router.post('/logout',logout);

export default router;
