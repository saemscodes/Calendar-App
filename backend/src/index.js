/**
 * SafeTrack Backend — Vercel Serverless Entry Point
 *
 * Vercel runs this as a serverless function, meaning:
 *   - There is no persistent http.server or Socket.IO.
 *   - Real-time events (location, SOS, ping) are dispatched via
 *     Supabase Realtime Broadcast instead of Socket.IO.
 *   - The module exports `app` so Vercel can handle incoming requests.
 *
 * Supabase Realtime channel layout:
 *   Channel "user:<userId>"  — private per-user events (SOS, ping, contact)
 *   Channel "loc:<userId>"   — live location updates (joined by contacts)
 *
 * Clients subscribe to these channels directly from the browser / mobile
 * using the Supabase JS/Swift/Kotlin SDK with a JWT for authentication.
 */
require('express-async-errors');
require('dotenv').config();

const express = require('express');
const cors    = require('cors');
const helmet  = require('helmet');
const morgan  = require('morgan');

const { prisma }          = require('./config/db');
const authRouter          = require('./routes/auth');
const usersRouter         = require('./routes/users');
const contactsRouter      = require('./routes/contacts');
const locationRouter      = require('./routes/location');
const sosRouter           = require('./routes/sos');
const trackersRouter      = require('./routes/trackers');
const pingsRouter         = require('./routes/pings');
const settingsRouter      = require('./routes/settings');
const smsWebhookRouter    = require('./routes/smsWebhook');
const { startCronJobs }   = require('./jobs');
const { errorHandler }    = require('./middleware/errorHandler');
const { supabaseAdmin }   = require('./config/supabase');

const app = express();

// ─── Middleware ────────────────────────────────────────────────────────────
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({
  origin: process.env.CORS_ORIGIN || 'https://calendar-safetrack.vercel.app',
  credentials: true,
}));
app.use(express.json({ limit: '1mb' }));
app.use(morgan('dev'));

// ─── Expose supabaseAdmin for route handlers ────────────────────────────────
// Routes call req.app.get('supabase').channel(...).send(...) to broadcast.
app.set('supabase', supabaseAdmin);

// ─── API Routes ────────────────────────────────────────────────────────────
const api = express.Router();
api.use('/auth',     authRouter);
api.use('/users',    usersRouter);
api.use('/contacts', contactsRouter);
api.use('/location', locationRouter);
api.use('/sos',      sosRouter);
api.use('/trackers', trackersRouter);
api.use('/pings',    pingsRouter);
api.use('/settings', settingsRouter);
app.use('/api/v1', api);

// ─── SMS Webhook (no JWT) ─────────────────────────────────────────────────
app.use('/webhook/sms', smsWebhookRouter);

// ─── Health ───────────────────────────────────────────────────────────────
app.get('/health', (_req, res) =>
  res.json({ status: 'ok', timestamp: new Date().toISOString() })
);

// ─── Error Handler ────────────────────────────────────────────────────────
app.use(errorHandler);

// ─── Cron Jobs ────────────────────────────────────────────────────────────
// On Vercel, cron runs are triggered by Vercel Cron (see vercel.json crons).
// For local dev, start them normally.
if (process.env.NODE_ENV !== 'production') {
  startCronJobs();
  const PORT = process.env.PORT || 4000;
  app.listen(PORT, () =>
    console.log(`🚀 SafeTrack backend running locally on http://localhost:${PORT}`)
  );
}

// ─── Graceful shutdown (local only) ──────────────────────────────────────
process.on('SIGTERM', async () => { await prisma.$disconnect(); });

// ─── Export for Vercel ────────────────────────────────────────────────────
module.exports = app;
