
import { z } from "zod";


// Load .env file in non-production environments if not already loaded by CLI
if (process.env.NODE_ENV !== 'production') {
    try {
      process.loadEnvFile();
    } catch {
      // Ignore if .env file does not exist (e.g. Docker/CI injects vars directly)
    }
  }

const envSchema = z.object({
    NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
    PORT: z.coerce.number().int().positive().default(3000),
    HOST: z.string().default('0.0.0.0'),
    POSTGRES_USER: z.string(),
    POSTGRES_PASSWORD: z.string(),
    POSTGRES_DB: z.string(),
    POSTGRES_PORT: z.coerce.number().int().positive().default(5432),
    POSTGRES_HOST: z.string(),
    POSTGRES_HOST_AUTH_METHOD: z.string().default('trust'),
    DATABASE_URL: z.string().optional(),
    JWT_ACCESS_SECRET: z.string(),
    JWT_REFRESH_SECRET: z.string(),
    JWT_ACCESS_EXPIRES_IN: z.string().default('15m'),
    JWT_REFRESH_EXPIRES_IN: z.string().default('7d'),
    // Comma-separated browser origins allowed for CORS (with credentials)
    CORS_ORIGIN: z.string().min(1),
    // Base URL used in verification / reset links (usually the frontend)
    APP_PUBLIC_URL: z.string().url().default('http://localhost:5173'),
})

const parsed = envSchema.safeParse(process.env);

if (!parsed.success) {
    console.error('❌ Invalid environment variables:');
    console.error(z.prettifyError(parsed.error));
    process.exit(1);
}


export const env = {
  ...parsed.data,
  DATABASE_URL: `postgresql://${parsed.data.POSTGRES_USER}:${parsed.data.POSTGRES_PASSWORD}@${parsed.data.POSTGRES_HOST}:${parsed.data.POSTGRES_PORT}/${parsed.data.POSTGRES_DB}`,
  CORS_ORIGINS: parsed.data.CORS_ORIGIN.split(',').map((o) => o.trim()).filter(Boolean),
}