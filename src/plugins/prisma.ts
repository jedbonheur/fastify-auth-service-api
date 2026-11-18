import fp from 'fastify-plugin';
import { FastifyInstance } from 'fastify';
import { FastifyPluginAsync } from 'fastify';
import { PrismaClient } from '../generated/prisma/client.js';
import { PrismaPg } from '@prisma/adapter-pg';
import pg from 'pg';
import { env } from '../config/env.js';

declare module 'fastify' {
  interface FastifyInstance {
    prisma: PrismaClient;
  }
}

const prismaPlugin: FastifyPluginAsync = async (fastify: FastifyInstance) => {
  const pool = new pg.Pool({ connectionString: env.DATABASE_URL });
  const adapter = new PrismaPg(pool);
  const prisma = new PrismaClient({ adapter });

  await prisma.$connect();
  fastify.decorate('prisma', prisma);

  fastify.addHook('onClose', async (server) => {
    await server.prisma.$disconnect();
    await pool.end();
  });
};

export default fp(prismaPlugin, { name: 'prisma' });
