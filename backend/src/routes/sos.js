const router = require('express').Router();
const { prisma } = require('../config/db');
const { authMiddleware } = require('../middleware/auth');
const { AppError } = require('../middleware/errorHandler');
const { broadcast } = require('../config/supabase');

router.use(authMiddleware);

// POST /api/v1/sos/trigger — fire an SOS event
router.post('/trigger', async (req, res) => {
  const triggeredById = req.user.sub;
  const { lat, lng, accuracy, mode, groupId } = req.body;

  if (lat == null || lng == null) throw new AppError('lat and lng required', 400);
  const sosMode = mode || 'SILENT_ALERT';

  // Resolve who to notify (group members or all accepted contacts)
  let notifyUserIds = [];
  if (groupId) {
    const members = await prisma.contactGroupMember.findMany({
      where: { groupId },
      select: { linkedUserId: true }
    });
    notifyUserIds = members.map(m => m.linkedUserId);
  } else {
    const links = await prisma.contactLink.findMany({
      where: {
        status: 'ACCEPTED',
        OR: [{ userAId: triggeredById }, { userBId: triggeredById }]
      }
    });
    notifyUserIds = links.map(l => l.userAId === triggeredById ? l.userBId : l.userAId);
  }

  if (notifyUserIds.length === 0) throw new AppError('No contacts to notify', 400);

  // Create SOS event + notifications in one transaction
  const event = await prisma.$transaction(async (tx) => {
    const ev = await tx.sosEvent.create({
      data: {
        triggeredById,
        mode: sosMode,
        lat, lng, accuracy,
        groupId,
        notifications: {
          create: notifyUserIds.map(id => ({
            notifiedId: id,
            status: 'SENT',
            pushedAt: new Date()
          }))
        }
      },
      include: { notifications: true }
    });
    return ev;
  });

  // Broadcast silent SOS alert via Supabase Realtime to each contact
  await Promise.all(notifyUserIds.map(uid =>
    broadcast(`user:${uid}`, 'sos:alert', {
      eventId: event.id,
      triggeredById,
      mode: sosMode,
      lat, lng, accuracy,
      timestamp: event.createdAt
    })
  ));

  // TODO: also send push notifications via APNs/FCM here
  // pushService.sendSosPush(notifyUserIds, event);

  res.status(201).json({ eventId: event.id, notifiedCount: notifyUserIds.length });
});

// PUT /api/v1/sos/:eventId/ack — a contact acknowledges the SOS
router.put('/:eventId/ack', async (req, res) => {
  const { eventId } = req.params;
  const notifiedId = req.user.sub;
  const { ackMessage } = req.body; // "Seen" | "On my way" | custom

  const notification = await prisma.sosNotification.findFirst({
    where: { sosEventId: eventId, notifiedId }
  });
  if (!notification) throw new AppError('SOS notification not found', 404);

  const ackStatus = ackMessage === 'On my way' ? 'ON_MY_WAY' : 'SEEN';
  const updated = await prisma.sosNotification.update({
    where: { id: notification.id },
    data: {
      status: ackStatus,
      seenAt: new Date(),
      ackAt: new Date(),
      ackMessage
    }
  });

  // Notify the SOS triggerer of the ack via Supabase Realtime
  const event = await prisma.sosEvent.findUnique({ where: { id: eventId } });
  await broadcast(`user:${event.triggeredById}`, 'sos:ack', {
    eventId,
    byUserId: notifiedId,
    status: ackStatus,
    ackMessage,
    at: updated.ackAt
  });

  res.json(updated);
});

// GET /api/v1/sos/events — own SOS events (triggered by me)
router.get('/events', async (req, res) => {
  const events = await prisma.sosEvent.findMany({
    where: { triggeredById: req.user.sub },
    include: { notifications: true },
    orderBy: { createdAt: 'desc' },
    take: 50
  });
  res.json(events);
});

// GET /api/v1/sos/inbox — SOS events where I was notified
router.get('/inbox', async (req, res) => {
  const notifications = await prisma.sosNotification.findMany({
    where: { notifiedId: req.user.sub },
    include: {
      sosEvent: {
        include: { triggeredBy: { select: { id: true, username: true, displayName: true } } }
      }
    },
    orderBy: { createdAt: 'desc' },
    take: 50
  });
  res.json(notifications);
});

// PUT /api/v1/sos/:eventId/resolve
router.put('/:eventId/resolve', async (req, res) => {
  const { eventId } = req.params;
  const event = await prisma.sosEvent.findUnique({ where: { id: eventId } });
  if (!event) throw new AppError('Event not found', 404);
  if (event.triggeredById !== req.user.sub) throw new AppError('Forbidden', 403);

  const updated = await prisma.sosEvent.update({
    where: { id: eventId },
    data: { resolvedAt: new Date() }
  });
  res.json(updated);
});

module.exports = router;
