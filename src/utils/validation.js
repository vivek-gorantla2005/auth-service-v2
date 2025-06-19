import { z } from "zod";

// Registration schema
const registrationSchema = z.object({
  username: z
    .string()
    .min(3, "Username must be at least 3 characters")
    .max(50, "Username can't exceed 50 characters"),
  email: z.string().email("Invalid email address"),
  password: z.string().min(6, "Password must be at least 6 characters"),
});

// Login schema
const loginSchema = z.object({
  email: z.string().email("Invalid email address"),
  password: z.string().min(6, "Password must be at least 6 characters"),
});


const validateRegistration = (data) => registrationSchema.safeParse(data);
const validateLogin = (data) => loginSchema.safeParse(data);

export default {
  validateRegistration,
  validateLogin,
};
