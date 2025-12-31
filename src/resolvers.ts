import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { prisma } from './db.js';
import { Response } from 'express';
import { throwError, ErrorCode } from './errors.js';

interface Context {
  res: Response;
  user?: {
    id: string;
    role: 'ADMIN' | 'EMPLOYEE';
    email: string;
  };
}

interface PaginationArgs {
  status?: 'PENDING' | 'IN_TRANSIT' | 'DELIVERED';
  limit?: number;
  offset?: number;
}

function assertIsAdmin(user: Context['user']): asserts user is NonNullable<Context['user']> {
  if (!user) {
    throwError('Authentication required', ErrorCode.UNAUTHENTICATED);
    throw new Error(); 
  }
  
  if ((user as any).role !== 'ADMIN') {
    throwError('Forbidden: Admin access required', ErrorCode.FORBIDDEN);
  }
}

export const resolvers = {
  Query: {
    me: (_: any, __: any, { user }: Context) => user,
    
    users: async (_: any, __: any, { user }: Context) => {
      assertIsAdmin(user);
      // user is now guaranteed to exist here
      return prisma.user.findMany({ select: { id: true, email: true, role: true } });
    },
    
    shipments: async (_: any, { status, limit = 10, offset = 0 }: PaginationArgs) => {
      try {
        return await prisma.shipment.findMany({
          where: status ? { status } : {},
          take: limit,
          skip: offset,
          orderBy: { createdAt: 'desc' }
        });
      } catch (e) {
        throwError('Failed to fetch shipments', ErrorCode.INTERNAL_SERVER_ERROR);
      }
    },
    
    shipment: async (_: any, { id }: { id: string }) => {
      const shipment = await prisma.shipment.findUnique({ where: { id } });
      if (!shipment) throwError('Shipment not found', ErrorCode.NOT_FOUND);
      return shipment;
    },
  },

  Mutation: {
    login: async (_: any, { email, password }: any, { res }: Context) => {
      const user = await prisma.user.findUnique({ where: { email } });
      // Fix 2: Check for user existence before using bcrypt
      if (!user || !(await bcrypt.compare(password, user.password))) {
        throwError('Invalid email or password', ErrorCode.UNAUTHENTICATED);
        return; // Unreachable, but satisfies TS
      }

      const accessToken = jwt.sign(
        { id: user.id, role: user.role, email: user.email }, 
        process.env.JWT_SECRET!, 
        { expiresIn: '15m' }
      );
      
      const refreshToken = jwt.sign(
        { id: user.id }, 
        process.env.REFRESH_SECRET!, 
        { expiresIn: '7d' }
      );

      await prisma.user.update({ where: { id: user.id }, data: { refreshToken } });

      const cookieOptions = { 
        httpOnly: true, 
        secure: true, 
        sameSite: 'none' as const,
        path: '/',
      };

      res.cookie('access_token', accessToken, { ...cookieOptions, maxAge: 15 * 60 * 1000 });
      res.cookie('refresh_token', refreshToken, { ...cookieOptions, maxAge: 7 * 24 * 60 * 60 * 1000 });

      return user;
    },

    logout: async (_: any, __: any, { user, res }: Context) => {
      if (user) {
        await prisma.user.update({ where: { id: user.id }, data: { refreshToken: null } });
      }
      res.clearCookie('access_token');
      res.clearCookie('refresh_token');
      return true;
    },

    createEmployee: async (_: any, { email, password }: any, { user }: Context) => {
      assertIsAdmin(user);
      try {
        const hashedPassword = await bcrypt.hash(password, 10);
        return await prisma.user.create({ 
          data: { email, password: hashedPassword, role: 'EMPLOYEE' } 
        });
      } catch (e) {
        throwError('User with this email already exists', ErrorCode.BAD_USER_INPUT);
      }
    },

    createShipment: async (_: any, args: any, { user }: Context) => {
      assertIsAdmin(user);
      try {
        return await prisma.shipment.create({ data: { ...args } });
      } catch (e) {
        throwError('Failed to create shipment. Check tracking ID uniqueness.', ErrorCode.BAD_USER_INPUT);
      }
    },

    updateShipmentStatus: async (_: any, { id, status }: any, { user }: Context) => {
      if (!user) throwError('Authentication required', ErrorCode.UNAUTHENTICATED);
      try {
        return await prisma.shipment.update({ where: { id }, data: { status } });
      } catch (e) {
        throwError('Failed to update status', ErrorCode.BAD_USER_INPUT);
      }
    },

    deleteShipment: async (_: any, { id }: { id: string }, { user }: Context) => {
      assertIsAdmin(user);
      try {
        await prisma.shipment.delete({ where: { id } });
        return true;
      } catch (e) {
        throwError('Shipment not found', ErrorCode.NOT_FOUND);
      }
    }
  }
};
