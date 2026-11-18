import { FastifyInstance } from "fastify";
import { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from "zod";

const messageSchema = z.object({
    message: z.string(),
})


const meResponseSchema = z.object({
    id: z.string().optional(),
    email: z.string().optional(),
    firstName: z.string().optional(),
    lastName: z.string().optional(),
    createdAt: z.date().optional(),
    message: z.string().optional(),
})
const updateNameBodySchema = z.object({
    firstName: z.string().min(1),
    lastName: z.string().min(1),
})

const meSchema = {
    response: {
        200: meResponseSchema,
        400: messageSchema,
        404: messageSchema,
    },
}   

const deleteUserSchema = {
    response: {
        200: messageSchema,
        400: messageSchema,
        404: messageSchema,
    },
}

const updateNameSchema = {
    body: updateNameBodySchema,
    response: {
        200: messageSchema,
        400: messageSchema,
        404: messageSchema,
    },
}

export async function usersRoutes(fastify: FastifyInstance) {
    const app = fastify.withTypeProvider<ZodTypeProvider>();
    
    app.get('/me',{schema: meSchema, preHandler: fastify.authenticate}, async (request, reply) => {
        
        try {
            const id = (request.user as {sub: string}).sub;
            const user = await fastify.prisma.user.findUnique({
                where: {
                    id,
                },
            })
            if (!user) {
                return reply.status(404).send({ message: 'User not found' });
            }
            
            return reply.status(200).send({
                id: user.id,
                email: user.email,
                firstName: user.firstName ,
                lastName: user.lastName,
                createdAt: user.createdAt,
            })
        } catch (error) {
            reply.status(400).send({ message: 'Invalid request'});
        }
    })
    app.patch('/name',{ schema: updateNameSchema, preHandler: fastify.authenticate}, async (request, reply) => {
        try {
            const id = (request.user as {sub: string}).sub;
            const { firstName, lastName } = request.body;
            await fastify.prisma.user.update({
                where: {
                    id,
                },
                data: {
                    firstName,
                    lastName,
                },
            })
            return reply.status(200).send({
                message: 'Name updated successfully',
            })
        } catch (error) {
            console.error(error);
            reply.status(400).send({ message: 'Invalid request'});
        }
    })

    app.delete('/me', {schema: deleteUserSchema, preHandler: fastify.authenticate}, async (request, reply) => {
            try {
            const id = (request.user as {sub: string}).sub;
            await fastify.prisma.user.delete({
                where: {
                    id,
                },
            })
            return reply.status(200).send({
                message: 'User deleted successfully',
            })
        }catch (error) {
            console.error(error);
            reply.status(400).send({ message: 'Invalid request'});
        }
    })
}