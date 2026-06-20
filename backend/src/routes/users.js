const router = require('express').Router();
const { prisma } = require('../config/db');
const { authMiddleware } = require('../middleware/auth');
const { AppError } = require('../middleware/errorHandler');

router.use(authMiddleware);

// GET /api/v1/users/me — own profile
router.get('/me', async (req, res) => {
  const user = await prisma.user.findUnique({
    where: { id: req.user.sub },
    select: { id: true, username: true, phone: true, displayName: true, avatarUrl: true, createdAt: true }
  });
  res.json(user);
});

// GET /api/v1/users/search?q=...  (by username, phone, or npub)
router.get('/search', async (req, res) => {
  const q = (req.query.q || '').trim();
  if (q.length < 2) throw new AppError('Search query must be at least 2 characters', 400);

  const users = await prisma.user.findMany({
    where: {
      AND: [
        { id: { not: req.user.sub } }, // exclude self
        {
          OR: [
            { username: { contains: q, mode: 'insensitive' } },
            { phone: { contains: q } },
            { npub: { contains: q, mode: 'insensitive' } },
          ]
        }
      ]
    },
    select: { id: true, username: true, displayName: true, avatarUrl: true, npub: true },
    take: 20
  });
  res.json(users);
});

// PUT /api/v1/users/me — update profile
router.put('/me', async (req, res) => {
  const { displayName, avatarUrl } = req.body;
  const updated = await prisma.user.update({
    where: { id: req.user.sub },
    data: { displayName, avatarUrl },
    select: { id: true, username: true, displayName: true, avatarUrl: true }
  });
  res.json(updated);
});

module.exports = router;
