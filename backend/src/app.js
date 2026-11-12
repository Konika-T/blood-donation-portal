// app.js – Express app (exported separately so tests can import it without starting the server)
require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const mongoSanitize = require('express-mongo-sanitize');
const morgan = require('morgan');
const errorHandler = require('./middleware/errorHandler');
const routes = require('./routes');

const app = express();

// Render (and most hosts) put a reverse proxy in front of the app.
// Without this, every visitor looks like the same IP and shares ONE rate-limit bucket.
app.set('trust proxy', 1);

// Security headers
app.use(helmet());

// CORS – allow origins listed in CLIENT_URL env (comma-separated)
// Trailing slashes are stripped so https://app.vercel.app/ still matches https://app.vercel.app
const allowedOrigins = (process.env.CLIENT_URL || '').split(',').map(o => o.trim().replace(/\/+$/, '')).filter(Boolean);
app.use(cors({
  origin: (origin, cb) => {
    // Allow Postman / server-to-server (no origin) and whitelisted origins
    if (!origin || allowedOrigins.includes(origin)) return cb(null, true);
    cb(new Error('CORS not allowed: ' + origin));
  },
  credentials: true,
}));

// Body parsing
app.use(express.json());

// Block NoSQL injection (strips keys starting with $ or containing .)
app.use(mongoSanitize());

// Request logging (skip in test to keep output clean)
if (process.env.NODE_ENV !== 'test') app.use(morgan('dev'));

// Global rate limit – 100 requests per 15 minutes
const globalLimit = rateLimit({ windowMs: 15 * 60 * 1000, max: 100 });
app.use(globalLimit);

// Tighter limit on auth endpoints
const authLimit = rateLimit({ windowMs: 15 * 60 * 1000, max: 10 });
app.use('/api/auth/login', authLimit);
app.use('/api/auth/register', authLimit);

// All routes
app.use('/api', routes);

// Central error handler (must be last)
app.use(errorHandler);

module.exports = app;
