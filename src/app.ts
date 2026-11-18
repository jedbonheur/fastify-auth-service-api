import Fastify from 'fastify';
import cors from '@fastify/cors';
import fjwt from '@fastify/jwt';
import pinoPretty from 'pino-pretty'; 
import cookie from '@fastify/cookie';
import rateLimit from '@fastify/rate-limit';

import helmet from '@fastify/helmet';
import {
  serializerCompiler,
  validatorCompiler,
  ZodTypeProvider,
} from 'fastify-type-provider-zod';
import prismaPlugin from './plugins/prisma.js';
import { authRoutes, sessionsRoutes } from './modules/auth/auth.service.js';
import { env } from './config/env.js';
import { usersRoutes } from './modules/users/users.service.js';
import authPlugin from './plugins/auth.js';
import mailerPlugin from './plugins/mailer.js';

export function buildApp() {
  const app = Fastify({
    logger: env.NODE_ENV === 'development'
    ?{
      transport: {
        target: 'pino-pretty',
        options: {
          colorize: true,
          translateTime: 'HH:MM:ss',
          ignore: 'pid,hostname',
        },
      },
    } : { level: 'info' },
  }).withTypeProvider<ZodTypeProvider>();

  // 1. Set Zod compilers for automatic validation & serialization
  app.setValidatorCompiler(validatorCompiler);
  app.setSerializerCompiler(serializerCompiler);

  // 2. Register security & utility plugins
  app.register(helmet, {
    contentSecurityPolicy: false, // less relevant for a pure JSON API
    crossOriginResourcePolicy: { policy: 'cross-origin' }, // if browsers call you cross-origin
  });
  app.register(cors, {
    origin: env.CORS_ORIGINS,
    credentials: true, // Required for HttpOnly refresh cookies
  });

  app.register(rateLimit, {
    global: false, // only routes that opt in via config.rateLimit
  });

  app.register(cookie);

  // Access JWT — short-lived, used by authenticate / Bearer header
  app.register(fjwt, {
    secret: env.JWT_ACCESS_SECRET,
    namespace: 'access',
    jwtSign: 'accessJwtSign',
    jwtVerify: 'accessJwtVerify',
  });

    // Refresh JWT — long-lived, cookie only, verified on /refresh
  app.register(fjwt, {
    secret: env.JWT_REFRESH_SECRET,
    namespace: 'refresh',
    jwtSign: 'refreshJwtSign',
    jwtVerify: 'refreshJwtVerify',
  });

  // 3. Register infrastructure plugins
  app.register(prismaPlugin);

  app.register(authPlugin);
  app.register(mailerPlugin);

  // 4. Register health check & feature routes
  app.get('/health', async (request, reply) => {return reply.status(200).send({ status: 'ok' })});
  app.get('/ready', async (request, reply) => {
    try {
      await Promise.race([
        app.prisma.$queryRaw`SELECT 1`,
        new Promise((_, reject) =>
          setTimeout(() => reject(new Error('db timeout')), 2000),
        ),
      ]);
      return reply.status(200).send({ status: 'ok' });
    } catch {
      return reply.status(503).send({ status: 'error', message: 'Database unavailable' });
    }
  });
  app.register(authRoutes, { prefix: '/api/auth' });
  app.register(sessionsRoutes, { prefix: '/api/sessions' });
  app.register(usersRoutes, { prefix: '/api/user' });
  return app;
}
