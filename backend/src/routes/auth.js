const router = require('express').Router();
const bcrypt = require('bcryptjs');
const { prisma } = require('../config/db');
const { signAccessToken, signRefreshToken, verifyRefreshToken } = require('../config/jwt');
const { AppError } = require('../middleware/errorHandler');
const { authMiddleware } = require('../middleware/auth');

// POST /api/v1/auth/register
router.post('/register', async (req, res) => {
  const { username, phone, password, displayName } = req.body;
  if (!username || !phone || !password) {
    throw new AppError('username, phone, and password are required', 400);
  }
  const hash = await bcrypt.hash(password, 12);
  const user = await prisma.user.create({
    data: {
      username: username.toLowerCase().trim(),
      phone: phone.trim(),
      passwordHash: hash,
      displayName: displayName || username,
      settings: {
        create: {} // default settings
      }
    },
    select: { id: true, username: true, phone: true, displayName: true, createdAt: true }
  });

  const accessToken = signAccessToken({ sub: user.id, username: user.username });
  const refreshToken = signRefreshToken({ sub: user.id });
  await prisma.refreshToken.create({
    data: {
      token: refreshToken,
      userId: user.id,
      expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)
    }
  });

  res.status(201).json({ user, accessToken, refreshToken });
});

// POST /api/v1/auth/login
router.post('/login', async (req, res) => {
  const { usernameOrPhone, password } = req.body;
  if (!usernameOrPhone || !password) {
    throw new AppError('usernameOrPhone and password are required', 400);
  }
  const user = await prisma.user.findFirst({
    where: {
      OR: [
        { username: usernameOrPhone.toLowerCase().trim() },
        { phone: usernameOrPhone.trim() }
      ]
    }
  });
  if (!user) throw new AppError('Invalid credentials', 401);

  const valid = await bcrypt.compare(password, user.passwordHash);
  if (!valid) throw new AppError('Invalid credentials', 401);

  const accessToken = signAccessToken({ sub: user.id, username: user.username });
  const refreshToken = signRefreshToken({ sub: user.id });
  await prisma.refreshToken.create({
    data: {
      token: refreshToken,
      userId: user.id,
      expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)
    }
  });

  res.json({
    user: { id: user.id, username: user.username, phone: user.phone, displayName: user.displayName },
    accessToken,
    refreshToken
  });
});

// POST /api/v1/auth/refresh
router.post('/refresh', async (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) throw new AppError('refreshToken required', 400);

  let decoded;
  try {
    decoded = verifyRefreshToken(refreshToken);
  } catch {
    throw new AppError('Invalid refresh token', 401);
  }

  const stored = await prisma.refreshToken.findUnique({ where: { token: refreshToken } });
  if (!stored || stored.expiresAt < new Date()) {
    throw new AppError('Refresh token expired or revoked', 401);
  }

  // Rotate refresh token
  await prisma.refreshToken.delete({ where: { token: refreshToken } });
  const newRefresh = signRefreshToken({ sub: decoded.sub });
  await prisma.refreshToken.create({
    data: {
      token: newRefresh,
      userId: decoded.sub,
      expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)
    }
  });

  const accessToken = signAccessToken({ sub: decoded.sub });
  res.json({ accessToken, refreshToken: newRefresh });
});

// POST /api/v1/auth/logout
router.post('/logout', async (req, res) => {
  const { refreshToken } = req.body;
  if (refreshToken) {
    await prisma.refreshToken.deleteMany({ where: { token: refreshToken } });
  }
  res.json({ ok: true });
});

// ─────────────────────────────────────────────────────────────
const SUPPORTED_SEED_LANGUAGES = ['en', 'am', 'ti', 'fr', 'es', 'zh-cn'];

// POST /api/v1/auth/seed-phrase
// Stores a bcrypt-hashed mnemonic phrase for the authenticated user.
// The raw phrase_joined is hashed server-side and then discarded.
// Requires: valid access token (Authorization: Bearer <token>)
router.post('/seed-phrase', authMiddleware, async (req, res) => {
  const { phrase_joined, language = 'en', word_count, entropy_fingerprint } = req.body;
  if (!phrase_joined) throw new AppError('phrase_joined required', 400);

  const words = phrase_joined.trim().split(/\s+/).filter(Boolean);
  if (words.length !== 12 && words.length !== 24) {
    throw new AppError('Phrase must be 12 or 24 words', 400);
  }
  if (!SUPPORTED_SEED_LANGUAGES.includes(language)) {
    throw new AppError('Unsupported language', 400);
  }

  // Hash with cost 12 (appropriate for a recovery phrase used infrequently)
  const phraseHash = await bcrypt.hash(phrase_joined.toLowerCase().trim(), 12);

  await prisma.seedPhraseRecovery.upsert({
    where: { userId: req.user.sub },
    create: {
      userId: req.user.sub,
      phraseHash,
      language,
      wordCount: word_count ?? words.length,
      entropyFingerprint: entropy_fingerprint ?? null,
    },
    update: {
      phraseHash,
      language,
      wordCount: word_count ?? words.length,
      entropyFingerprint: entropy_fingerprint ?? null,
    },
  });

  // phrase_joined goes out of scope here — GC-eligible
  res.json({ ok: true, language, word_count: words.length });
});

// GET /api/v1/auth/seed-exists
// Returns whether the authenticated user has a stored recovery phrase.
// Does NOT reveal the hash or any phrase information.
router.get('/seed-exists', authMiddleware, async (req, res) => {
  const record = await prisma.seedPhraseRecovery.findUnique({
    where: { userId: req.user.sub },
    select: { language: true, wordCount: true, createdAt: true },
  });
  if (!record) {
    return res.json({ exists: false });
  }
  res.json({
    exists: true,
    language: record.language,
    word_count: record.wordCount,
    created_at: record.createdAt,
  });
});

// POST /api/v1/auth/seed-verify
// Account recovery via mnemonic phrase for users using the Node.js backend path.
// Validates phrase against the stored bcrypt hash, then issues new tokens.
// This endpoint deliberately has a fixed 500ms artificial delay to prevent
// timing attacks that could distinguish between valid and invalid hashes.
// IMPORTANT: This is the Node backend fallback; Supabase users use auth-seed Edge Fn.
router.post('/seed-verify', async (req, res) => {
  const { username_or_phone, phrase_joined } = req.body;
  if (!username_or_phone || !phrase_joined) {
    throw new AppError('username_or_phone and phrase_joined are required', 400);
  }

  const words = phrase_joined.trim().split(/\s+/).filter(Boolean);
  if (words.length !== 12 && words.length !== 24) {
    // Fixed-time artificial delay to match the bcrypt comparison duration
    await new Promise(r => setTimeout(r, 500));
    throw new AppError('Invalid recovery phrase', 401);
  }

  // Look up user
  const user = await prisma.user.findFirst({
    where: {
      OR: [
        { username: username_or_phone.toLowerCase().trim() },
        { phone: username_or_phone.trim() },
      ],
    },
    select: { id: true, username: true, phone: true, displayName: true },
  });

  if (!user) {
    await new Promise(r => setTimeout(r, 500));
    throw new AppError('Invalid recovery phrase', 401);
  }

  // Get stored hash
  const record = await prisma.seedPhraseRecovery.findUnique({
    where: { userId: user.id },
    select: { phraseHash: true },
  });

  if (!record) {
    await new Promise(r => setTimeout(r, 500));
    throw new AppError('Invalid recovery phrase', 401);
  }

  // Verify bcrypt (inherently slow, provides timing uniformity)
  const valid = await bcrypt.compare(phrase_joined.toLowerCase().trim(), record.phraseHash);
  if (!valid) throw new AppError('Invalid recovery phrase', 401);

  // Issue new tokens
  const accessToken = signAccessToken({ sub: user.id, username: user.username });
  const refreshToken = signRefreshToken({ sub: user.id });
  await prisma.refreshToken.create({
    data: {
      token: refreshToken,
      userId: user.id,
      expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
    },
  });

  res.json({
    user: { id: user.id, username: user.username, phone: user.phone, displayName: user.displayName },
    accessToken,
    refreshToken,
  });
});

module.exports = router;
