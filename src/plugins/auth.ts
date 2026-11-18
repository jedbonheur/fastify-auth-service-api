import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import type { FastifyJwtNamespace } from '@fastify/jwt';
import fp from 'fastify-plugin';

type AccessJwt = FastifyJwtNamespace<{
  namespace: 'access';
  jwtSign: 'accessJwtSign';
  jwtVerify: 'accessJwtVerify';
}>;

type RefreshJwt = FastifyJwtNamespace<{
  namespace: 'refresh';
  jwtSign: 'refreshJwtSign';
  jwtVerify: 'refreshJwtVerify';
}>;

declare module 'fastify' {
  interface FastifyInstance {
    authenticate: (request: FastifyRequest, reply: FastifyReply) => Promise<void>;
  }

  // Sign helpers are decorated on reply at runtime
  interface FastifyReply
    extends Pick<AccessJwt, 'accessJwtSign'>,
      Pick<RefreshJwt, 'refreshJwtSign'> {}

  // Verify helpers are decorated on request at runtime
  interface FastifyRequest
    extends Pick<AccessJwt, 'accessJwtVerify'>,
      Pick<RefreshJwt, 'refreshJwtVerify'> {}
}

declare module '@fastify/jwt' {
  interface FastifyJWT {
    namespaces: 'access' | 'refresh';
    payload: { sub: string; email: string; typ: 'access' | 'refresh' };
    user: { sub: string; email: string; typ: 'access' | 'refresh' };
  }
}

const authPlugin = async (fastify: FastifyInstance) => {
  fastify.decorate('authenticate', async (request, reply) => {
    try {
      // IMPORTANT: verify with ACCESS secret only
      await request.accessJwtVerify();

      if (request.user.typ !== 'access') {
        return reply.status(401).send({ message: 'Invalid token type' });
      }
    } catch {
      return reply.status(401).send({ message: 'Unauthorized' });
    }
  });
};

export default fp(authPlugin, {
  name: 'auth',
});
