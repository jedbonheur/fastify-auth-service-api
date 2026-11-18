import { FastifyInstance } from "fastify";
import { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from "zod";
import { AppError, ErrorCodes } from '../../lib/errors.js';

const messageSchema = z.object({
    message: z.string(),
});

const errorSchema = z.object({
    code: z.string(),
    message: z.string(),
});

const meResponseSchema = z.object({
    id: z.string().optional(),
    email: z.string().optional(),
    firstName: z.string().optional(),
    lastName: z.string().optional(),
    createdAt: z.date().optional(),
    message: z.string().optional(),
});

const updateNameBodySchema = z.object({
    firstName: z.string().min(1),
    lastName: z.string().min(1),
});

const meSchema = {
    tags: ['user'],
    summary: 'Get current user',
    security: [{ bearerAuth: [] }],
    response: {
        200: meResponseSchema,
        404: errorSchema,
    },
};

const deleteUserSchema = {
    tags: ['user'],
    summary: 'Delete current user',
    security: [{ bearerAuth: [] }],
    response: {
        200: messageSchema,
        404: errorSchema,
    },
};

const updateNameSchema = {
    tags: ['user'],
    summary: 'Update current user name',
    security: [{ bearerAuth: [] }],
    body: updateNameBodySchema,
    response: {
        200: messageSchema,
        404: errorSchema,
    },
};

export async function usersRoutes(fastify: FastifyInstance) {
    const app = fastify.withTypeProvider<ZodTypeProvider>();

    app.get('/me', { schema: meSchema, preHandler: fastify.authenticate }, async (request, reply) => {
        const id = (request.user as { sub: string }).sub;
        const user = await fastify.prisma.user.findUnique({
            where: { id },
        });

        if (!user) {
            throw new AppError(ErrorCodes.USER_NOT_FOUND, 'User not found', 404);
        }

        return reply.status(200).send({
            id: user.id,
            email: user.email,
            firstName: user.firstName,
            lastName: user.lastName,
            createdAt: user.createdAt,
        });
    });

    app.patch('/name', { schema: updateNameSchema, preHandler: fastify.authenticate }, async (request, reply) => {
        const id = (request.user as { sub: string }).sub;
        const { firstName, lastName } = request.body;

        try {
            await fastify.prisma.user.update({
                where: { id },
                data: { firstName, lastName },
            });
        } catch {
            throw new AppError(ErrorCodes.USER_NOT_FOUND, 'User not found', 404);
        }

        return reply.status(200).send({
            message: 'Name updated successfully',
        });
    });

    app.delete('/me', { schema: deleteUserSchema, preHandler: fastify.authenticate }, async (request, reply) => {
        const id = (request.user as { sub: string }).sub;

        try {
            await fastify.prisma.user.delete({
                where: { id },
            });
        } catch {
            throw new AppError(ErrorCodes.USER_NOT_FOUND, 'User not found', 404);
        }

        return reply.status(200).send({
            message: 'User deleted successfully',
        });
    });
}
