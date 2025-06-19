import User from "../models/User.js";
import logger from "../utils/logger.js";
import generateToken from "../utils/generateToken.js";
import validator from "../utils/validation.js";
import RefreshToken from "../models/RefreshToken.js";
import { redis } from "../server.js";

const { validateRegistration, validateLogin } = validator;

// Cache registration and login data
const registerCache = async ({ username, email, userId, refreshToken }) => {
  await redis.set(
    `user:${userId}`,
    JSON.stringify({ userId, username, email, refreshToken }),
    'EX',
    60 * 60 * 24 // 1 day
  );
  await redis.set(`emailToUserId:${email}`, userId.toString(), 'EX', 60 * 60 * 24);
};

const loginCache = async ({ user }) => {
  await redis.set(
    `user:${user._id}`,
    JSON.stringify({
      userId: user._id,
      username: user.username,
      email: user.email,
    }),
    'EX',
    60 * 60 * 24
  );
  await redis.set(`emailToUserId:${user.email}`, user._id.toString(), 'EX', 60 * 60 * 24);
};

// Register user
const registerUser = async (req, res) => {
  logger.info("Register endpoint hit...");

  try {
    const result = validateRegistration(req.body);
    if (!result.success) {
      const errors = result.error.flatten().fieldErrors;
      logger.warn("Validation error", errors);
      return res.status(400).json({ success: false, message: errors });
    }

    const { email, password, username } = req.body;

    let user = await User.findOne({ $or: [{ email }, { username }] });
    if (user) {
      logger.warn(`${username} or ${email} already exists`);
      return res.status(409).json({ success: false, message: "User already exists!" });
    }

    user = new User({ username, email, password });
    await user.save();
    logger.info("User saved successfully", user._id);

    const { accessToken, refreshToken } = await generateToken(user);

    await registerCache({ username, email, userId: user._id, refreshToken });

    return res.status(201).json({
      success: true,
      message: "User registered successfully",
      accessToken,
      refreshToken,
    });
  } catch (err) {
    logger.error("Registration error occurred", err);
    return res.status(500).json({
      success: false,
      message: "Internal server error",
      error: err.message,
    });
  }
};

// Login user
const login = async (req, res) => {
  try {
    logger.info("Login endpoint hit");

    const result = validateLogin(req.body);
    if (!result.success) {
      const errorMsg = result.error.flatten().fieldErrors;
      logger.warn("Validation error:", errorMsg);
      return res.status(400).json({ success: false, message: errorMsg });
    }

    const { email, password } = req.body;

    let user;
    const userIdFromCache = await redis.get(`emailToUserId:${email}`);

    if (userIdFromCache) {
      const cachedUser = await redis.get(`user:${userIdFromCache}`);
      if (cachedUser) {
        const parsed = JSON.parse(cachedUser);
        logger.info(`User found in Redis: ${parsed.userId}`);
        user = await User.findById(parsed.userId);
      }
    }

    // Fallback to DB
    if (!user) {
      user = await User.findOne({ email });
      if (!user) {
        logger.warn("User not found");
        return res.status(404).json({ status: false, message: "User not found" });
      }
      await loginCache({ user });
    }

    const isValidPass = await user.comparePassword(password);
    if (!isValidPass) {
      logger.warn("Invalid password");
      return res.status(401).json({ status: false, message: "Invalid password" });
    }

    const { accessToken, refreshToken } = await generateToken(user);

    return res.status(200).json({
      success: true,
      message: "User logged in successfully",
      accessToken,
      refreshToken,
      userId: user._id,
    });
  } catch (err) {
    logger.error("Login error occurred", err);
    return res.status(500).json({
      success: false,
      message: "Internal server error",
      error: err.message,
    });
  }
};

// Refresh token
const refresh_token = async (req, res) => {
  try {
    logger.info("refresh token endpoint hit");

    const { refreshToken } = req.body;
    if (!refreshToken) {
      logger.warn("Refresh token missing");
      return res.status(400).json({ success: false, message: "Refresh token required" });
    }

    const blacklisted = await redis.get(`bl:${refreshToken}`);
    if (blacklisted) {
      logger.warn("Refresh token is blacklisted");
      return res.status(403).json({ success: false, message: "Refresh token is blacklisted" });
    }

    const reftoken = await RefreshToken.findOne({ token: refreshToken });
    if (!reftoken) {
      logger.warn("Refresh token not found in DB");
      return res.status(404).json({ success: false, message: "Refresh token not found" });
    }

    if (reftoken.expiresAt < new Date()) {
      await RefreshToken.deleteOne({ _id: reftoken._id });
      logger.info("Refresh token expired");
      return res.status(403).json({ success: false, message: "Refresh token expired" });
    }

    const { accessToken, refreshToken: newRefreshToken } = await generateToken(reftoken.user);

    reftoken.token = newRefreshToken;
    reftoken.expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
    await reftoken.save();

    logger.info("Tokens refreshed");
    return res.status(200).json({
      success: true,
      message: "Tokens refreshed successfully",
      accessToken,
      refreshToken: newRefreshToken,
      userId: reftoken.user._id
    });
  } catch (err) {
    logger.error("Refresh error occurred", err);
    return res.status(500).json({
      success: false,
      message: "Internal server error",
      error: err.message,
    });
  }
};

// Logout
const logout = async (req, res) => {
  try {
    logger.info("Logout endpoint hit");

    const { refreshToken } = req.body;
    if (!refreshToken) {
      logger.warn("No refresh token in request");
      return res.status(400).json({
        success: false,
        message: "Refresh token is required to logout",
      });
    }

    const deleted = await RefreshToken.deleteOne({ token: refreshToken });
    if (deleted.deletedCount === 0) {
      logger.warn("Refresh token not found or already invalidated");
      return res.status(404).json({
        success: false,
        message: "Refresh token not found or already logged out",
      });
    }

    await redis.set(`bl:${refreshToken}`, "blacklisted", "EX", 7 * 24 * 60 * 60); // 7 days

    logger.info("Logout successful");
    return res.status(200).json({
      success: true,
      message: "User logged out successfully",
    });
  } catch (err) {
    logger.error("Logout error occurred", err);
    return res.status(500).json({
      success: false,
      message: "Internal server error",
      error: err.message,
    });
  }
};

export default {
  registerUser,
  login,
  refresh_token,
  logout,
};
