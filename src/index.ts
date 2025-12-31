import 'dotenv/config';
import express from 'express';
import { createHandler } from 'graphql-http/lib/use/express';
import { makeExecutableSchema } from '@graphql-tools/schema';
import cookieParser from 'cookie-parser';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import { prisma } from './db.js';
import { typeDefs } from './schema.js';
import { resolvers } from './resolvers.js';
import { ErrorCode } from './errors.js';

const schema = makeExecutableSchema({ typeDefs, resolvers });
const app = express();

app.set('trust proxy', 1); 

app.use(cors({ 
  origin: "https://thriving-melba-7fc957.netlify.app", 
  credentials: true 
}));

app.use(cookieParser());
app.use(express.json());

app.options('(.*)', cors());

app.post('/refresh_token', async (req, res) => {
  const token = req.cookies.refresh_token;
  if (!token) return res.status(401).send({ ok: false, message: "No refresh token" });

  try {
    const payload: any = jwt.verify(token, process.env.REFRESH_SECRET!);
    const user = await prisma.user.findUnique({ where: { id: payload.id } });
    
    if (!user || user.refreshToken !== token) {
      res.clearCookie('access_token');
      res.clearCookie('refresh_token');
      return res.status(403).send({ ok: false, message: "Invalid session" });
    }

    const accessToken = jwt.sign(
      { id: user.id, role: user.role, email: user.email }, 
      process.env.JWT_SECRET!, 
      { expiresIn: '15m' }
    );
    
    res.cookie('access_token', accessToken, { 
      httpOnly: true, 
      secure: true, 
      sameSite: 'none', 
      maxAge: 15 * 60 * 1000 
    });

    return res.send({ ok: true });
  } catch (e) {
    return res.status(401).send({ ok: false, message: "Token expired" });
  }
});



app.all('/graphql', createHandler({
  schema,
  context: async (req) => {
    const rawReq = req.raw as any; 
    const rawRes = (req as any).raw.res; 

    console.log("Incoming Cookies:", rawReq.cookies);

    const token = rawReq.cookies?.access_token;
    let user = null;

    if (token) {
      try {
        user = jwt.verify(token, process.env.JWT_SECRET!);
      } catch (e) {
      }
    }
    
    return { user, res: rawRes };
  },
  // Global error formatting
  onOperation: (_req, _args, result) => {
    if (result.errors) {
      result.errors.forEach((err) => {
        console.error(`[GraphQL Error]: ${err.message}`, {
          code: err.extensions?.code,
          path: err.path,
        });
      });
    }
  },
}));

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(`🚀 Server ready at Port ${PORT}`));
