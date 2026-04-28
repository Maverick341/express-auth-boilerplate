import { z } from "zod";
import dotenv from "dotenv";

dotenv.config({
    path: "./.env"
});

const envSchema = z.object({
  NODE_ENV: z.enum(["development", "production", "test"]).default("development"),

  PORT: z
    .string()
    .default("4000")
    .transform((val) => parseInt(val, 10)),

  CLIENT_URL: z.string().url(),
  BASE_URL: z.string().url(),

  MONGO_URL: z.string().min(1, "MONGO_URL is required"),

  CORS_ORIGIN: z.string().default("*"),

  // Mailtrap
  MAILTRAP_SMTP_HOST: z.string().min(1),
  MAILTRAP_SMTP_PORT: z
    .string()
    .default("587")
    .transform((val) => parseInt(val, 10)),
  MAILTRAP_SMTP_USER: z.string().min(1),
  MAILTRAP_SMTP_PASS: z.string().min(1),
  MAILTRAP_SENDEREMAIL: z.string().email(),

  // Auth Tokens
  TEMP_TOKEN_SECRET: z.string().min(1, "TEMP_TOKEN_SECRET is required"),

  ACCESS_TOKEN_SECRET: z.string().min(1, "ACCESS_TOKEN_SECRET is required"),
  ACCESS_TOKEN_EXPIRY: z.string().default("15m"),

  REFRESH_TOKEN_SECRET: z.string().min(1, "REFRESH_TOKEN_SECRET is required"),
  REFRESH_TOKEN_EXPIRY: z.string().default("7d"),

  // Google OAuth
  GOOGLE_CLIENT_ID: z.string().optional(),
  GOOGLE_CLIENT_SECRET: z.string().optional(),
  GOOGLE_REDIRECT_URI: z.string().url(),

  GOOGLE_JWKS_URL: z.string().url(),

  // GitHub OAuth
  GITHUB_CLIENT_ID: z.string().optional(),
  GITHUB_CLIENT_SECRET: z.string().optional(),
  GITHUB_REDIRECT_URI: z.string().url(),

  // Misc
  FORGOT_PASSWORD_REDIRECT_URL: z.string().url().optional(),

  // Cloudinary
  CLOUDINARY_CLOUD_NAME: z.string().min(1),
  CLOUDINARY_API_KEY: z.string().min(1),
  CLOUDINARY_API_SECRET: z.string().min(1),
});

const parsedEnv = envSchema.parse(process.env);

export const env = parsedEnv;