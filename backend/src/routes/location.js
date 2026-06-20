const router = require('express').Router();
const { prisma } = require('../config/db');
const { authMiddleware } = require('../middleware/auth');
const { AppError } = require('../middleware/errorHandler');
const { broadcast } = require('../config/supabase');

router.use(authMiddleware);

// Helper: check mutual accepted link between A and B
async function hasAcceptedLink(userAId, userBId) {
  const link = await prisma.contactLink.findFirst({
    where: {
      status: 'ACCEPTED',
      OR: [
        { userAId, userBId },
        { userAId: userBId, userBId: userAId }
      ]
    }
  });
  return !!link;
}

// POST /api/v1/location/update — device pushes its own location
router.post('/update', async (req, res) => {
  const userId = req.user.sub;
  const { lat, lng, accuracy, altitude, speed, bearing, batteryPct, source, pingMechanism, trackerTagId } = req.body;

  if (lat == null || lng == null) throw new AppError('lat and lng required', 400);

  const locationSource = source || 'NATIVE_GPS';
  const now = new Date();

  // Upsert current location
  const current = await prisma.currentLocation.upsert({
    where: { userId },
    create: { userId, lat, lng, accuracy, altitude, speed, bearing, batteryPct, source: locationSource, trackerTagId },
    update: { lat, lng, accuracy, altitude, speed, bearing, batteryPct, source: locationSource, trackerTagId, updatedAt: now }
  });

  // Append to history
  const settings = await prisma.userSettings.findUnique({ where: { userId } });
  await prisma.locationHistory.create({
    data: {
      userId,
      lat, lng, accuracy, altitude, speed, bearing, batteryPct,
      source: locationSource,
      pingMechanism: pingMechanism || null,
      trackerTagId: trackerTagId || null,
      recordedAt: now
    }
  });

  // Broadcast live location to all accepted contacts via Supabase Realtime
  const links = await prisma.contactLink.findMany({
    where: {
      status: 'ACCEPTED',
      OR: [{ userAId: userId }, { userBId: userId }]
    }
  });

  const contactIds = links.map(l => l.userAId === userId ? l.userBId : l.userAId);
  await Promise.all(contactIds.map(contactId =>
    broadcast(`loc:${contactId}`, 'location:update', {
      userId,
      lat, lng, accuracy,
      batteryPct,
      source: locationSource,
      timestamp: now
    })
  ));

  // If this was triggered by a remote ping, mark the ping as responded
  if (source === 'REMOTE_PING_FORCED') {
    await prisma.remotePing.updateMany({
      where: { targetId: userId, status: 'DELIVERED' },
      data: { status: 'RESPONDED', respondedAt: now, responseLat: lat, responseLng: lng }
    });
  }

  res.json({ ok: true, current });
});

// GET /api/v1/location/current/:userId — last known location
router.get('/current/:userId', async (req, res) => {
  const { userId } = req.params;
  const requesterId = req.user.sub;

  if (userId !== requesterId) {
    const linked = await hasAcceptedLink(requesterId, userId);
    if (!linked) throw new AppError('Access denied — no active contact link', 403);
  }

  const loc = await prisma.currentLocation.findUnique({ where: { userId } });
  if (!loc) throw new AppError('No location data yet', 404);
  res.json(loc);
});

// GET /api/v1/location/history/:userId — trail
router.get('/history/:userId', async (req, res) => {
  const { userId } = req.params;
  const requesterId = req.user.sub;
  const { limit = 500, since } = req.query;

  if (userId !== requesterId) {
    const linked = await hasAcceptedLink(requesterId, userId);
    if (!linked) throw new AppError('Access denied — no active contact link', 403);
  }

  const where = { userId };
  if (since) where.recordedAt = { gte: new Date(since) };

  const history = await prisma.locationHistory.findMany({
    where,
    orderBy: { recordedAt: 'desc' },
    take: parseInt(limit, 10)
  });
  res.json(history);
});

// GET /api/v1/location/watchers — who can see my location
router.get('/watchers', async (req, res) => {
  const userId = req.user.sub;
  const links = await prisma.contactLink.findMany({
    where: {
      status: 'ACCEPTED',
      OR: [{ userAId: userId }, { userBId: userId }]
    },
    include: {
      userA: { select: { id: true, username: true, displayName: true, avatarUrl: true } },
      userB: { select: { id: true, username: true, displayName: true, avatarUrl: true } }
    }
  });

  const watchers = links.map(link => {
    const other = link.userAId === userId ? link.userB : link.userA;
    return { linkId: link.id, user: other };
  });
  res.json(watchers);
});

module.exports = router;
