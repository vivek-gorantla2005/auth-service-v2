import express from "express";
import dotenv from "dotenv";
import logger from "./utils/logger.js";
import cors from "cors";
import helmet from "helmet";
import { RateLimiterRedis } from "rate-limiter-flexible";
import router from "./routes/identity-service.js";
import errorHandler from "./middlewares/errorHandler.js";
import connectMongoDB from "./utils/connect-mongoDB.js";
import Redis from "ioredis";
import { rateLimit } from "express-rate-limit";

dotenv.config();

// Connect to MongoDB
connectMongoDB();

// Connect to Redis
const redis = new Redis(process.env.REDIS_URL);
redis.on("connect", () => logger.warn("Connected to Redis"));
redis.on("error", (err) => logger.error("Redis error:", err));

// Initialize Express
const app = express();
const port = process.env.PORT || 3001;

// 💡 Express-based rate limiter for general web abuse (non-Redis, memory-based)
const expressRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 100,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  handler: (req, res) => {
    logger.warn(`Express Rate limiting exceeded for IP: ${req.ip}`);
    res.status(429).json({ status: false, message: "Too many requests sent (express)" });
  },
});

// Apply express-rate-limit to all API routes
app.use('/api', expressRateLimiter);

// Basic Middlewares
app.use(helmet());
app.use(cors());
app.use(express.json());
app.use((req, res, next) => {
  logger.info(`Received ${req.method} to ${req.url}`);
  logger.info(`Request body, ${JSON.stringify(req.body)}`);
  next();
});
// Error handler
app.use(errorHandler);

// Redis-powered global limiter (stronger, more precise control)
const globalLimiter = new RateLimiterRedis({
  storeClient: redis,
  points: 10,
  duration: 1, // 10 req/sec
  keyPrefix: 'rl-global',
});

app.use(async (req, res, next) => {
  try {
    await globalLimiter.consume(req.ip);
    next();
  } catch {
    logger.warn(`Redis global limiter exceeded for IP: ${req.ip}`);
    res.status(429).json({ success: false, message: "Too many requests (redis global)" });
  }
});

// Redis-powered limiter for /register endpoint
const registerLimiter = new RateLimiterRedis({
  storeClient: redis,
  points: 10,
  duration: 15 * 60,
  keyPrefix: 'rl-register',
});

const registerLimiterMiddleware = async (req, res, next) => {
  try {
    await registerLimiter.consume(req.ip);
    next();
  } catch {
    logger.warn(`Sensitive limiter exceeded for IP: ${req.ip}`);
    res.status(429).json({ status: false, message: "Too many requests to /register (redis)" });
  }
};

app.use("/api/auth/register", registerLimiterMiddleware);

// Routes
app.use("/api/auth", router);


// Start server
app.listen(port, () => {
  logger.info(`Identity service running on port: ${port}`);
  console.log(`Server running on http://localhost:${port}`);
});
