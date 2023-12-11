const rateLimit = require('express-rate-limit');
const Blockedips = require('../models/blockedip');

const limiter = rateLimit({
  windowMs: 2000,
  max: 1,
  handler: async (req, res, next) => {
    const ip = req.body.ip || req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    try {
      const blockedIp = new Blockedips({
        ip: ip,
        blockType: 'Bruteforce',
      });
      await blockedIp.save();
    } catch (error) {
      console.error('Error saving blocked IP:', error);
    }
    return res.status(429).json({ message: 'Too many requests from this IP, we recognize this as bruteforce attack!' });
  },
});

module.exports = limiter;