import type { FastifyRequest } from 'fastify';
import type { PrismaClient, Prisma } from '../../generated/prisma/client.js';
import type { AuditEventType } from '../../generated/prisma/enums.js';

type RecordAuditInput = {
  event: AuditEventType;
  userId?: string | null;
  email?: string | null;
  request?: FastifyRequest;
  meta?: Prisma.InputJsonValue;
};

/**
 * Best-effort audit write. Never throws to the caller —
 * a full disk must not turn a successful login into a 500.
 */
export async function recordAudit(
  prisma: PrismaClient,
  input: RecordAuditInput,
): Promise<void> {
  try {
    await prisma.auditEvent.create({
      data: {
        event: input.event,
        userId: input.userId ?? null,
        email: input.email ?? null,
        ip: input.request?.ip ?? null,
        userAgent: input.request?.headers['user-agent']?.toString() ?? null,
        meta: input.meta ?? undefined,
      },
    });
  } catch (err) {
    console.error('audit write failed', input.event, err);
  }
}
