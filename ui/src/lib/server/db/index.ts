import { PrismaClient } from '@prisma/client'
export { Version, Action, Protocol } from '@prisma/client';

// expose a singleton
export const prisma = new PrismaClient()

export default prisma;