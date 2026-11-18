import { FastifyInstance, FastifyError } from 'fastify';
import fp from 'fastify-plugin';
import { AppError, ErrorCodes } from '../lib/errors.js';

const errorHandlerPlugin = async (fastify: FastifyInstance) => {
  fastify.setErrorHandler((error: FastifyError | AppError | Error, request, reply) => {
    if (error instanceof AppError) {
      return reply.status(error.statusCode).send({
        code: error.code,
        message: error.message,
      });
    }

    // Zod / Fastify validation (bad body, params, etc.)
    if ('validation' in error && error.validation) {
      return reply.status(400).send({
        code: ErrorCodes.AUTH_VALIDATION_FAILED,
        message: error.message,
      });
    }

    request.log.error(error);

    const statusCode =
      'statusCode' in error &&
      typeof error.statusCode === 'number' &&
      error.statusCode >= 400
        ? error.statusCode
        : 500;

    return reply.status(statusCode).send({
      code: ErrorCodes.INTERNAL_ERROR,
      message:
        statusCode >= 500 ? 'Internal server error' : error.message,
    });
  });
};

export default fp(errorHandlerPlugin, {
  name: 'error-handler',
});
