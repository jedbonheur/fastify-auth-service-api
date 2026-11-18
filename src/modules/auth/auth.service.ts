import { FastifyInstance } from 'fastify';
import { ZodTypeProvider } from 'fastify-type-provider-zod';
import bcrypt from 'bcrypt';
import { z } from 'zod';
import { env } from '../../config/env.js';
import { createHash, randomBytes } from 'node:crypto';
import '@fastify/cookie';

const EMAIL_VERIFY_TTL_MS = 24 * 60 * 60 * 1000; // 24h
const PASSWORD_RESET_TTL_MS = 60 * 60 * 1000; // 1h

// Shared response schemas
export const messageSchema = z.object({
  message: z.string(),
});

// Register password: length + basic complexity (letter + digit)
const passwordSchema = z
  .string()
  .min(8)
  .regex(/[A-Za-z]/, 'Password must contain at least one letter')
  .regex(/[0-9]/, 'Password must contain at least one digit');

// Register request / response validation
const registerBodySchema = z.object({
  firstName: z.string().min(1),
  lastName: z.string().min(1),
  email: z.email(),
  password: passwordSchema,
});

const registerResponseSchema = z.object({
  id: z.string(),
  email: z.string(),
  firstName: z.string(),
  lastName: z.string(),
  message: z.literal("User created successfully"),
});

const registerSchema = {
  body: registerBodySchema,
  response: {
    201: registerResponseSchema,
    400: messageSchema,
    409: messageSchema,
  },
};

// Login request / response validation
const loginBodySchema = z.object({
  email: z.email(),
  password: z.string().min(8),
});

const loginResponseSchema = z.object({
  userId: z.string(),
  accessToken: z.string(),
  accessTokenExpiresIn: z.number(),
  refreshTokenExpiresIn: z.number(),
  email: z.string(),
  message: z.literal("Login successful"),
});

const loginSchema = {
  body: loginBodySchema,
  response: {
    200: loginResponseSchema,
    401: messageSchema,
    403: messageSchema,
    500: messageSchema,
  },
};

// Email verification / password lifecycle
const tokenBodySchema = z.object({
  token: z.string().min(1),
});

const emailBodySchema = z.object({
  email: z.email(),
});

const verifyEmailSchema = {
  body: tokenBodySchema,
  response: {
    200: messageSchema,
    400: messageSchema,
  },
};

const resendVerificationSchema = {
  body: emailBodySchema,
  response: {
    200: messageSchema,
  },
};

const forgotPasswordSchema = {
  body: emailBodySchema,
  response: {
    200: messageSchema,
  },
};

const resetPasswordSchema = {
  body: z.object({
    token: z.string().min(1),
    password: passwordSchema,
  }),
  response: {
    200: messageSchema,
    400: messageSchema,
  },
};

const changePasswordSchema = {
  body: z.object({
    currentPassword: z.string().min(8),
    newPassword: passwordSchema,
  }),
  response: {
    200: messageSchema,
    400: messageSchema,
    401: messageSchema,
  },
};

// Refresh token response validation
const refreshResponseSchema = z.object({
  accessToken: z.string(),
  accessTokenExpiresIn: z.number(),
  message: z.literal('Token refreshed'),
});

const refreshSchema = {
  response: {
    200: refreshResponseSchema,
    401: messageSchema,
  },
};

// Logout response validation
const logoutSchema = {
  response: {
    200: messageSchema,
    401: messageSchema,
  },
};

// Sessions list / revoke validation
const sessionItemSchema = z.object({
  id: z.string(),
  userAgent: z.string().nullable(),
  ip: z.string().nullable(),
  createdAt: z.date(),
  lastUsedAt: z.date(),
  expiresAt: z.date(),
  isCurrent: z.boolean(),
});

const sessionsListResponseSchema = z.object({
  sessions: z.array(sessionItemSchema),
});

const sessionsListSchema = {
  response: {
    200: sessionsListResponseSchema,
    401: messageSchema,
  },
};

const sessionIdParamsSchema = z.object({
  id: z.string().uuid(),
});

const revokeOneSchema = {
  params: sessionIdParamsSchema,
  response: {
    200: messageSchema,
    401: messageSchema,
    404: messageSchema,
  },
};

const revokeOthersSchema = {
  response: {
    200: messageSchema,
    401: messageSchema,
  },
};

// Convert env durations like "15m" / "7d" into milliseconds
function durationToMs(duration: string): number {
  const match = /^(\d+)([smhd])$/.exec(duration);
  if (!match) {
    throw new Error(`Invalid duration: ${duration}`);
  }
  const value = Number(match[1]);
  const unit = match[2] as 's' | 'm' | 'h' | 'd';
  const multipliers = { s: 1000, m: 60_000, h: 3_600_000, d: 86_400_000 } as const;
  return value * multipliers[unit];
}

const accessTokenTtlMs = durationToMs(env.JWT_ACCESS_EXPIRES_IN);
const refreshTokenTtlMs = durationToMs(env.JWT_REFRESH_EXPIRES_IN);

// HttpOnly cookie options for the refresh token
const refreshCookieOptions = {
  httpOnly: true,
  secure: env.NODE_ENV === 'production',
  sameSite: 'lax' as const,
  path: '/api/auth',
  maxAge: Math.floor(refreshTokenTtlMs / 1000),
};

// Hash opaque tokens (refresh + one-time) for DB lookup / storage
function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

function hashRefreshToken(token: string): string {
  return hashToken(token);
}

function generateOpaqueToken(): string {
  return randomBytes(32).toString('hex');
}

async function issueOneTimeToken(
  prisma: FastifyInstance['prisma'],
  userId: string,
  type: 'email_verify' | 'password_reset',
  ttlMs: number,
): Promise<string> {
  // Invalidate unused tokens of the same type for this user
  await prisma.oneTimeToken.updateMany({
    where: { userId, type, usedAt: null },
    data: { usedAt: new Date() },
  });

  const rawToken = generateOpaqueToken();
  await prisma.oneTimeToken.create({
    data: {
      userId,
      type,
      tokenHash: hashToken(rawToken),
      expiresAt: new Date(Date.now() + ttlMs),
    },
  });
  return rawToken;
}

// Prisma filter for currently usable refresh sessions
function activeSessionWhere(userId: string) {
  return {
    userId,
    revokedAt: null,
    replacedById: null,
    expiresAt: { gt: new Date() },
  };
}

/** Revoke this session and every successor linked via replacedById (session family / chain). */
async function revokeSessionChain(
  prisma: FastifyInstance['prisma'],
  start: { id: string; replacedById: string | null },
) {
  const ids: string[] = [];
  let current: { id: string; replacedById: string | null } | null = start;

  while (current) {
    ids.push(current.id);
    if (!current.replacedById) break;
    current = await prisma.refreshSession.findUnique({
      where: { id: current.replacedById },
      select: { id: true, replacedById: true },
    });
  }

  if (ids.length > 0) {
    await prisma.refreshSession.updateMany({
      where: { id: { in: ids } },
      data: { revokedAt: new Date() },
    });
  }
}

export async function authRoutes(fastify: FastifyInstance) {
  const app = fastify.withTypeProvider<ZodTypeProvider>();

  // POST /register — create a new user account
  app.post(
    '/register',
    {
      schema: registerSchema,
      config: {
        rateLimit: { max: 5, timeWindow: '15 minutes' },
      },
    },
    async (request, reply) => {
      const { email, firstName, lastName, password } = request.body;

      // Hash password before storing
      const passwordHash = await bcrypt.hash(password, 10);

      try {
        const user = await fastify.prisma.user.create({
          data: {
            email,
            firstName,
            lastName,
            passwordHash,
          },
        });

        const rawToken = await issueOneTimeToken(
          fastify.prisma,
          user.id,
          'email_verify',
          EMAIL_VERIFY_TTL_MS,
        );
        const verifyUrl = `${env.APP_PUBLIC_URL}/verify-email?token=${rawToken}`;
        await fastify.mailer.sendEmailVerification(user.email, verifyUrl);

        return reply.status(201).send({
          id: user.id,
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
          message: "User created successfully",
        });
      } catch (error: any) {
        if (error.code === 'P2002') {
          return reply.status(409).send({ message: "User already exists, try a different email" });
        }
        return reply.status(400).send({ message: "Failed to create user" });
      }
    }
  );

  // POST /login — verify credentials, issue tokens, persist refresh session
  app.post('/login', {
    schema: loginSchema,
    config: {
      rateLimit: { max: 10, timeWindow: '15 minutes' },
    },
  }, async (request, reply) => {
    const { email, password } = request.body;

    try {
      // Look up user by email
      const user = await fastify.prisma.user.findUnique({
        where: { email },
      });

      if (!user) {
        return reply.status(401).send({ message: "Invalid email or password" });
      }

      // Verify password
      const isPasswordValid = await bcrypt.compare(password, user.passwordHash);

      if (!isPasswordValid) {
        return reply.status(401).send({ message: "Invalid email or password" });
      }

      if (!user.emailVerifiedAt) {
        return reply.status(403).send({ message: 'Email not verified' });
      }

      if (user.status !== 'active') {
        return reply.status(403).send({ message: 'Account is not active' });
      }

      // Issue short-lived access token
      const accessToken = await reply.accessJwtSign({
        sub: user.id,
        email: user.email,
        typ: 'access',
      }, {
        expiresIn: env.JWT_ACCESS_EXPIRES_IN,
      });

      // Issue long-lived refresh token
      const refreshToken = await reply.refreshJwtSign({
        sub: user.id,
        email: user.email,
        typ: 'refresh',
      }, {
        expiresIn: env.JWT_REFRESH_EXPIRES_IN,
      });

      // Persist hashed refresh token as a session row
      const refreshTokenHash = hashRefreshToken(refreshToken);

      await fastify.prisma.refreshSession.create({
        data: {
          userId: user.id,
          tokenHash: refreshTokenHash,
          expiresAt: new Date(Date.now() + refreshTokenTtlMs),
          userAgent: request.headers['user-agent'],
          ip: request.ip,
        },
      });

      // Store refresh token in HttpOnly cookie
      reply.setCookie('refreshToken', refreshToken, refreshCookieOptions);

      return reply.status(200).send({
        userId: user.id,
        accessToken,
        accessTokenExpiresIn: accessTokenTtlMs,
        refreshTokenExpiresIn: refreshTokenTtlMs,
        email: user.email,
        message: "Login successful",
      });
    } catch (error) {
      return reply.status(500).send({ message: "Internal server error" });
    }
  });

  // POST /refresh — validate session, rotate refresh token, return new access token
  app.post('/refresh', {
    schema: refreshSchema,
    config: {
      rateLimit: { max: 30, timeWindow: '15 minutes' },
    },
  }, async (request, reply) => {
    const refreshToken = request.cookies.refreshToken;

    if (!refreshToken) {
      return reply.status(401).send({ message: 'Unauthorized' });
    }

    try {
      // Verify refresh JWT (request.user is unset here — no authenticate preHandler)
      const payload = fastify.jwt.refresh.verify<{ sub: string; email: string, typ: 'access' | 'refresh' }>(
        refreshToken,
      );

      
      if (payload.typ !== 'refresh') {
        return reply.status(401).send({ message: 'Unauthorized' });
      }

      // Look up refresh session by token hash
      const refreshTokenHash = hashRefreshToken(refreshToken);
      const refreshSession = await fastify.prisma.refreshSession.findUnique({
        where: { tokenHash: refreshTokenHash },
      });

      if (!refreshSession || refreshSession.userId !== payload.sub) {
        return reply.status(401).send({ message: 'Unauthorized' });
      }

      // Reuse detection: token was already rotated — revoke the whole session chain
      if (refreshSession.replacedById) {
        await revokeSessionChain(fastify.prisma, refreshSession);
        reply.clearCookie('refreshToken', { path: '/api/auth' });
        return reply.status(401).send({ message: 'Unauthorized' });
      }

      // Normal invalid (logout revoke, expiry)
      if (refreshSession.revokedAt || refreshSession.expiresAt <= new Date()) {
        return reply.status(401).send({ message: 'Unauthorized' });
      }

      // Confirm the session user still exists
      const user = await fastify.prisma.user.findUnique({
        where: { id: refreshSession.userId },
      });
      if (!user) {
        return reply.status(401).send({ message: 'Unauthorized' });
      }

      // Issue a new access token
      const accessToken = await reply.accessJwtSign({
        sub: user.id,
        email: user.email,
        typ: 'access',
      }, {
        expiresIn: env.JWT_ACCESS_EXPIRES_IN,
      });

      // Rotate: issue a new refresh token and persist a new session
      const newRefreshToken = await reply.refreshJwtSign({
        sub: user.id,
        email: user.email,
        typ: 'refresh',
      }, {
        expiresIn: env.JWT_REFRESH_EXPIRES_IN,
      });

      const newRefreshTokenHash = hashRefreshToken(newRefreshToken);
      const newRefreshSession = await fastify.prisma.refreshSession.create({
        data: {
          userId: user.id,
          tokenHash: newRefreshTokenHash,
          expiresAt: new Date(Date.now() + refreshTokenTtlMs),
          userAgent: request.headers['user-agent'],
          ip: request.ip,
        },
      });

      // Mark old session as replaced + revoked so it drops out of active lists
      await fastify.prisma.refreshSession.update({
        where: { id: refreshSession.id },
        data: {
          replacedById: newRefreshSession.id,
          revokedAt: new Date(),
          lastUsedAt: new Date(),
        },
      });

      // Replace cookie with rotated refresh token
      reply.setCookie('refreshToken', newRefreshToken, refreshCookieOptions);

      return reply.status(200).send({
        accessToken,
        accessTokenExpiresIn: accessTokenTtlMs,
        message: 'Token refreshed',
      });
    } catch (error) {
      console.error(error);
      reply.clearCookie('refreshToken', { path: '/api/auth' });
      return reply.status(401).send({ message: 'Unauthorized' });
    }
  });

  // POST /verify-email — consume email_verify one-time token
  app.post('/verify-email', {
    schema: verifyEmailSchema,
    config: {
      rateLimit: { max: 10, timeWindow: '15 minutes' },
    },
  }, async (request, reply) => {
    const { token } = request.body;
    const tokenHash = hashToken(token);

    const record = await fastify.prisma.oneTimeToken.findUnique({
      where: { tokenHash },
    });

    if (
      !record ||
      record.type !== 'email_verify' ||
      record.usedAt ||
      record.expiresAt <= new Date()
    ) {
      return reply.status(400).send({ message: 'Invalid or expired verification token' });
    }

    await fastify.prisma.$transaction([
      fastify.prisma.user.update({
        where: { id: record.userId },
        data: { emailVerifiedAt: new Date() },
      }),
      fastify.prisma.oneTimeToken.update({
        where: { id: record.id },
        data: { usedAt: new Date() },
      }),
    ]);

    return reply.status(200).send({ message: 'Email verified' });
  });

  // POST /resend-verification — issue a new email_verify token (opaque response)
  app.post('/resend-verification', {
    schema: resendVerificationSchema,
    config: {
      rateLimit: { max: 5, timeWindow: '15 minutes' },
    },
  }, async (request, reply) => {
    const { email } = request.body;
    const user = await fastify.prisma.user.findUnique({ where: { email } });

    if (user && !user.emailVerifiedAt) {
      const rawToken = await issueOneTimeToken(
        fastify.prisma,
        user.id,
        'email_verify',
        EMAIL_VERIFY_TTL_MS,
      );
      const verifyUrl = `${env.APP_PUBLIC_URL}/verify-email?token=${rawToken}`;
      await fastify.mailer.sendEmailVerification(user.email, verifyUrl);
    }

    return reply.status(200).send({
      message: 'If that email is registered and unverified, a verification link was sent',
    });
  });

  // POST /forgot-password — issue password_reset token (opaque response)
  app.post('/forgot-password', {
    schema: forgotPasswordSchema,
    config: {
      rateLimit: { max: 5, timeWindow: '15 minutes' },
    },
  }, async (request, reply) => {
    const { email } = request.body;
    const user = await fastify.prisma.user.findUnique({ where: { email } });

    if (user && user.emailVerifiedAt) {
      const rawToken = await issueOneTimeToken(
        fastify.prisma,
        user.id,
        'password_reset',
        PASSWORD_RESET_TTL_MS,
      );
      const resetUrl = `${env.APP_PUBLIC_URL}/reset-password?token=${rawToken}`;
      await fastify.mailer.sendPasswordReset(user.email, resetUrl);
    }

    return reply.status(200).send({
      message: 'If that email is registered, a password reset link was sent',
    });
  });

  // POST /reset-password — consume password_reset token, set new password, revoke sessions
  app.post('/reset-password', {
    schema: resetPasswordSchema,
    config: {
      rateLimit: { max: 10, timeWindow: '15 minutes' },
    },
  }, async (request, reply) => {
    const { token, password } = request.body;
    const tokenHash = hashToken(token);

    const record = await fastify.prisma.oneTimeToken.findUnique({
      where: { tokenHash },
    });

    if (
      !record ||
      record.type !== 'password_reset' ||
      record.usedAt ||
      record.expiresAt <= new Date()
    ) {
      return reply.status(400).send({ message: 'Invalid or expired reset token' });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    await fastify.prisma.$transaction([
      fastify.prisma.user.update({
        where: { id: record.userId },
        data: { passwordHash },
      }),
      fastify.prisma.oneTimeToken.update({
        where: { id: record.id },
        data: { usedAt: new Date() },
      }),
      fastify.prisma.refreshSession.updateMany({
        where: { userId: record.userId, revokedAt: null },
        data: { revokedAt: new Date() },
      }),
    ]);

    reply.clearCookie('refreshToken', { path: '/api/auth' });
    return reply.status(200).send({ message: 'Password reset successful' });
  });

  // POST /change-password — authenticated; revoke other sessions
  app.post('/change-password', {
    schema: changePasswordSchema,
    preHandler: fastify.authenticate,
    config: {
      rateLimit: { max: 10, timeWindow: '15 minutes' },
    },
  }, async (request, reply) => {
    const userId = request.user.sub;
    const { currentPassword, newPassword } = request.body;

    const user = await fastify.prisma.user.findUnique({ where: { id: userId } });
    if (!user) {
      return reply.status(401).send({ message: 'Unauthorized' });
    }

    const valid = await bcrypt.compare(currentPassword, user.passwordHash);
    if (!valid) {
      return reply.status(401).send({ message: 'Invalid current password' });
    }

    if (currentPassword === newPassword) {
      return reply.status(400).send({ message: 'New password must be different' });
    }

    const passwordHash = await bcrypt.hash(newPassword, 10);
    const refreshToken = request.cookies.refreshToken;
    const currentTokenHash = refreshToken ? hashRefreshToken(refreshToken) : null;

    await fastify.prisma.$transaction([
      fastify.prisma.user.update({
        where: { id: userId },
        data: { passwordHash },
      }),
      fastify.prisma.refreshSession.updateMany({
        where: {
          ...activeSessionWhere(userId),
          ...(currentTokenHash ? { tokenHash: { not: currentTokenHash } } : {}),
        },
        data: { revokedAt: new Date() },
      }),
    ]);

    return reply.status(200).send({ message: 'Password changed' });
  });

  // POST /logout — revoke via refresh cookie (works even if access token expired)
  app.post('/logout', { schema: logoutSchema }, async (request, reply) => {
    const refreshToken = request.cookies.refreshToken;

    const clear = () => reply.clearCookie('refreshToken', { path: '/api/auth' });

    if (!refreshToken) {
      clear();
      return reply.status(200).send({ message: 'Logged out' });
    }

    try {
      const payload = fastify.jwt.refresh.verify<{
        sub: string;
        email: string;
        typ: 'access' | 'refresh';
      }>(refreshToken);

      if (payload.typ === 'refresh') {
        const tokenHash = hashRefreshToken(refreshToken);
        const session = await fastify.prisma.refreshSession.findUnique({
          where: { tokenHash },
        });

        if (session && session.userId === payload.sub && !session.revokedAt) {
          await fastify.prisma.refreshSession.update({
            where: { id: session.id },
            data: { revokedAt: new Date() },
          });
        }
      }
    } catch {
      // Invalid/expired refresh — still clear cookie; logout is idempotent
    }

    clear();
    return reply.status(200).send({ message: 'Logged out' });
  });
}

// Session management routes — registered at /api/sessions
export async function sessionsRoutes(fastify: FastifyInstance) {
  const app = fastify.withTypeProvider<ZodTypeProvider>();

  // GET / — list my active sessions
  app.get('/', {
    schema: sessionsListSchema,
    preHandler: fastify.authenticate,
  }, async (request, reply) => {
    const userId = (request.user as { sub: string }).sub;
    const refreshToken = request.cookies.refreshToken;
    const currentTokenHash = refreshToken ? hashRefreshToken(refreshToken) : null;

    const sessions = await fastify.prisma.refreshSession.findMany({
      where: activeSessionWhere(userId),
      orderBy: { lastUsedAt: 'desc' },
      select: {
        id: true,
        tokenHash: true,
        userAgent: true,
        ip: true,
        createdAt: true,
        lastUsedAt: true,
        expiresAt: true,
      },
    });

    return reply.status(200).send({
      sessions: sessions.map(({ tokenHash, ...session }) => ({
        ...session,
        isCurrent: currentTokenHash !== null && tokenHash === currentTokenHash,
      })),
    });
  });

  // DELETE /:id — revoke one session
  app.delete('/:id', {
    schema: revokeOneSchema,
    preHandler: fastify.authenticate,
  }, async (request, reply) => {
    const userId = (request.user as { sub: string }).sub;
    const { id } = request.params;

    const session = await fastify.prisma.refreshSession.findFirst({
      where: { id, userId },
    });

    if (!session) {
      return reply.status(404).send({ message: 'Session not found' });
    }

    if (!session.revokedAt) {
      await fastify.prisma.refreshSession.update({
        where: { id: session.id },
        data: { revokedAt: new Date() },
      });
    }

    const refreshToken = request.cookies.refreshToken;
    if (refreshToken && hashRefreshToken(refreshToken) === session.tokenHash) {
      reply.clearCookie('refreshToken', { path: '/api/auth' });
    }

    return reply.status(200).send({ message: 'Session revoked' });
  });

  // DELETE / — revoke all other active sessions (keep current)
  app.delete('/', {
    schema: revokeOthersSchema,
    preHandler: fastify.authenticate,
  }, async (request, reply) => {
    const userId = (request.user as { sub: string }).sub;
    const refreshToken = request.cookies.refreshToken;
    const currentTokenHash = refreshToken ? hashRefreshToken(refreshToken) : null;

    await fastify.prisma.refreshSession.updateMany({
      where: {
        ...activeSessionWhere(userId),
        ...(currentTokenHash ? { tokenHash: { not: currentTokenHash } } : {}),
      },
      data: { revokedAt: new Date() },
    });

    return reply.status(200).send({ message: 'Other sessions revoked' });
  });
}
