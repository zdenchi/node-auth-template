import 'dotenv/config.js';
import * as Sentry from '@sentry/node';
import { ProfilingIntegration } from '@sentry/profiling-node';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import cors from 'cors';
import express, { json, Request, Response, NextFunction } from 'express';
import router from './routes/index.routes';

const app = express();
const { SENTRY_DSN, PORT, NODE_ENV } = process.env;
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN as unknown as string;
const ALLOWED_ORIGIN = process.env.FRONTEND_ORIGIN as unknown as string;

if (NODE_ENV === 'production') {
  if (!SENTRY_DSN) {
    console.error('SENTRY_DSN is not defined. Exiting...');
    process.exit(1);
  }

  Sentry.init({
    dsn: SENTRY_DSN,
    integrations: [
      new Sentry.Integrations.Http({ tracing: true }),
      new Sentry.Integrations.Express({ app }),
      new ProfilingIntegration(),
    ],
    tracesSampleRate: 0.1,
    profilesSampleRate: 0.1,
  });

  app.use(Sentry.Handlers.requestHandler());
  app.use(Sentry.Handlers.tracingHandler());
}

app.use(
  cors({
    origin: [ALLOWED_ORIGIN, FRONTEND_ORIGIN],
    credentials: true,
  })
);
app.use(helmet());
app.use(json({ limit: "10kb" }));
app.use(cookieParser());
app.use(router);

if (NODE_ENV === 'production') {
  app.use(Sentry.Handlers.errorHandler());
} else {
  app.use((err: any, req: Request, res: Response, next: NextFunction) => {
    console.log(`${err.message || JSON.stringify(err, null, 2)}`);
    const status = err.statusCode || 500;
    const message = err.message || 'Internal Server Error';
    res.status(status).json({ message });
  });
}

app.listen(PORT || 4000, () => {
  console.log(`🚀 Server ready on http://localhost:${PORT || 4000}`);
});
