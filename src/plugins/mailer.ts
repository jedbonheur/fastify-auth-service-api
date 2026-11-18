import fp from 'fastify-plugin';
import { FastifyInstance } from 'fastify';
import { ConsoleMailer, type Mailer } from '../modules/mail/mailer.js';

declare module 'fastify' {
  interface FastifyInstance {
    mailer: Mailer;
  }
}

const mailerPlugin = async (fastify: FastifyInstance) => {
  fastify.decorate('mailer', new ConsoleMailer());
};

export default fp(mailerPlugin, { name: 'mailer' });
