import Fastify from 'fastify';
import cors from '@fastify/cors';
import fjwt from '@fastify/jwt';
import cookie from '@fastify/cookie';
import rateLimit from '@fastify/rate-limit';
import swagger from '@fastify/swagger';
import swaggerUi from '@fastify/swagger-ui';
import { z } from 'zod';

import helmet from '@fastify/helmet';
import {
  serializerCompiler,
  validatorCompiler,
  ZodTypeProvider,
  jsonSchemaTransform,
} from 'fastify-type-provider-zod';
import prismaPlugin from './plugins/prisma.js';
import { authRoutes, sessionsRoutes } from './modules/auth/auth.service.js';
import { env } from './config/env.js';
import { usersRoutes } from './modules/users/users.service.js';
import authPlugin from './plugins/auth.js';
import mailerPlugin from './plugins/mailer.js';
import errorHandlerPlugin from './plugins/error-handler.js';

const healthResponseSchema = z.object({
  status: z.literal('ok'),
});

const readyErrorSchema = z.object({
  status: z.literal('error'),
  message: z.string(),
});

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

  // OpenAPI from Zod route schemas → browsable UI at /docs
  app.register(swagger, {
    openapi: {
      info: {
        title: 'Auth Service API',
        description: 'Standalone auth: register, login, sessions, account recovery',
        version: '1.0.0',
      },
      servers: [{ url: `http://localhost:${env.PORT}` }],
      components: {
        securitySchemes: {
          bearerAuth: {
            type: 'http',
            scheme: 'bearer',
            bearerFormat: 'JWT',
            description: 'Access token from POST /api/auth/login',
          },
        },
      },
      tags: [
        { name: 'auth', description: 'Register, login, tokens, password flows' },
        { name: 'sessions', description: 'List and revoke refresh sessions' },
        { name: 'user', description: 'Current user profile' },
        { name: 'health', description: 'Liveness / readiness' },
      ],
    },
    transform: jsonSchemaTransform,
  });

  app.register(swaggerUi, {
    routePrefix: '/docs',
  });

  // 2. Register security & utility plugins
  app.register(helmet, {
    contentSecurityPolicy: false, // less relevant for a pure JSON API; keeps /docs working
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

  app.register(errorHandlerPlugin);

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

  // 4. Feature routes (must be plugins so they register after swagger's onRoute hook)
  app.register(async (fastify) => {
    const typed = fastify.withTypeProvider<ZodTypeProvider>();

    typed.get('/health', {
      schema: {
        tags: ['health'],
        summary: 'Liveness probe',
        response: {
          200: healthResponseSchema,
        },
      },
    }, async (_request, reply) => {
      return reply.status(200).send({ status: 'ok' });
    });

    typed.get('/ready', {
      schema: {
        tags: ['health'],
        summary: 'Readiness probe (database)',
        response: {
          200: healthResponseSchema,
          503: readyErrorSchema,
        },
      },
    }, async (_request, reply) => {
      try {
        await Promise.race([
          fastify.prisma.$queryRaw`SELECT 1`,
          new Promise((_, reject) =>
            setTimeout(() => reject(new Error('db timeout')), 2000),
          ),
        ]);
        return reply.status(200).send({ status: 'ok' });
      } catch {
        return reply.status(503).send({ status: 'error', message: 'Database unavailable' });
      }
    });
  });

  app.register(authRoutes, { prefix: '/api/auth' });
  app.register(sessionsRoutes, { prefix: '/api/sessions' });
  app.register(usersRoutes, { prefix: '/api/user' });
  return app;
}
