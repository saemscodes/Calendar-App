const router = require('express').Router();
const { prisma } = require('../config/db');
const { authMiddleware } = require('../middleware/auth');
const { AppError } = require('../middleware/errorHandler');
const { REMOTE_PING_EXPIRY_MS } = require('../config/constants');
const { broadcast } = require('../config/supabase');

router.use(authMiddleware);

// POST /api/v1/pings/request — request a force-report from a target device
router.post('/request', async (req, res) => {
  const { targetUserId } = req.body;
  const issuerId = req.user.sub;

  if (!targetUserId) throw new AppError('targetUserId required', 400);

  // Verify there's an accepted link
  const link = await prisma.contactLink.findFirst({
    where: {
      status: 'ACCEPTED',
      OR: [
        { userAId: issuerId, userBId: targetUserId },
        { userAId: targetUserId, userBId: issuerId }
      ]
    }
  });
  if (!link) throw new AppError('No active contact link with this user', 403);

  const ping = await prisma.remotePing.create({
    data: { issuerId, targetId: targetUserId, status: 'QUEUED' }
  });

  // Push ping to target device via Supabase Realtime
  await broadcast(`user:${targetUserId}`, 'ping:forced', {
    pingId: ping.id,
    fromUserId: issuerId,
    timestamp: ping.queuedAt
  });

  // Mark as delivered (client will respond with location update)
  await prisma.remotePing.update({
    where: { id: ping.id },
    data: { status: 'DELIVERED', deliveredAt: new Date() }
  });

  // Auto-expire pings not responded to
  setTimeout(async () => {
    await prisma.remotePing.updateMany({
      where: { id: ping.id, status: 'DELIVERED' },
      data: { status: 'EXPIRED' }
    });
  }, REMOTE_PING_EXPIRY_MS);

  res.status(201).json(ping);
});

// GET /api/v1/pings — list pings I issued
router.get('/', async (req, res) => {
  const pings = await prisma.remotePing.findMany({
    where: { issuerId: req.user.sub },
    orderBy: { queuedAt: 'desc' },
    take: 20
  });
  res.json(pings);
});

module.exports = router;
