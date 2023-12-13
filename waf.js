const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const isAuth = require('./middleware/is-auth')
const rateLimiter = require('./middleware/rate-limiter')

const app = express();
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

const Iplist = require('./models/ip-list');
const CheckSchema = require('./models/check');
const Admin = require('./models/admin')
const Blockedips = require('./models/blockedip')

const corsOptions = {
  origin: 'https://akm-hackathon.vercel.app',
};

app.use(cors(corsOptions));

app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', 'https://akm-hackathon.vercel.app');
  res.setHeader('Access-Control-Allow-Methods', 'OPTIONS, GET, POST, PUT, PATCH, DELETE');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  next();
});

// Regular expressions for detecting malicious code
const sqlInjectionRegex = /\b(ALTER|CREATE|DELETE|DROP|EXEC(UTE){0,1}|INSERT( +INTO){0,1}|MERGE|REPLACE|SELECT|UPDATE|UNION( +ALL){0,1})\b|\b(AND|OR)\b.+\b(IS|IN|LIKE)\b|('[^']*'|[^\w\s.])/i;
const lfiRegex = /(?:\.\.\/|\/\.\.)/i;
const xssRegex = /<.*?>|<|>|<>/gi;
const commandRegex = /([|;&`\x00-\x1f()\[\]{}*$!#~^"])|(\b(rm|cat|touch|wget|curl|sh|bash|python|php)\b(?!\/\.\.))/;

app.get('/iplist', isAuth, async (req, res) => {
  try { 
    const ips = await Iplist.find();
    res.json(ips);
  } catch (error) {
    console.error('Error retrieving IP list:', error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});

app.post('/api/users', rateLimiter, async (req, res) => {
  const requestData = req.body.message;
  const ip = req.body.ip || req.headers['x-forwarded-for'] || req.socket.remoteAddress;

  try {
    const blockedIp = await Blockedips.findOne({ ip: ip, blockType: 'Bruteforce' });
    if (blockedIp) {
      return res.status(403).json({ message: 'Access Denied', blockType: "You were trying to do Bruteforce huh!?" });
    }
  } catch (error) {
    console.error('Error searching blocked IP:', error);
    return res.status(500).json({ message: 'Internal Server Error' });
  }

  let isMalicious = false;

  // Check for SQL injection
  if (sqlInjectionRegex.test(requestData)) {
    isMalicious = true;
    req.body.payloadType = 'SQL Injection';
  }

  // Check for LFI (Local File Inclusion)
  if (lfiRegex.test(requestData)) {
    isMalicious = true;
    req.body.payloadType = 'LFI (Local File Inclusion)';
  }

  // Check for XSS (Cross-Site Scripting)
  if (xssRegex.test(requestData)) {
    isMalicious = true;
    req.body.payloadType = 'XSS (Cross-Site Scripting)';
  }

  //Check for Command Injection
  if (commandRegex.test(requestData)) {
    isMalicious = true;
    req.body.payloadType = 'Command Injection'
  }

  let checkDocument;
  if (isMalicious) {
    try {
      checkDocument = await CheckSchema.findOneAndUpdate(
        { ip: ip },
        { $inc: { maliciousReqCount: 1 } },
        { upsert: true, new: true }
      );
      if (checkDocument.maliciousReqCount > 5) {
        const blockedIp = new Blockedips({
          ip: ip,
          blockType: 'Malicious Requests Exceeded'
        });
        await blockedIp.save();
        return res.status(403).json({ message: 'Access Denied', blockType: blockedIp.blockType });
      }
    } catch (error) {
      console.error('Error updating CheckSchema:', error);
    }
  }
  
  const IpList = new Iplist({
    ip: ip,
    message: requestData,
    isMalicious: isMalicious,
    payloadType: req.body.payloadType,
    check: checkDocument ? checkDocument._id : undefined,
  });
  
  try {
    const result = await IpList.save();
    res.status(200).json(result);
  } catch (error) {
    console.error('Error saving IP address:', error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});

app.get('/blockedips', (req, res, next) => {
  Blockedips.find().then(datas => {
    res.status(200).json({data: datas})
  })
})


app.post('/api/login', (req, res, next) => {
    const email = req.body.email
    const password = req.body.password
    let loadedAdmin;
    Admin.findOne({ email: email })
      .then(admin => {
        if (!admin) {
          const error = new Error("This is not the email of the admin")
          error.statusCode = 401
          throw error;
        }
        loadedAdmin = admin
        return bcrypt.compare(password, admin.password)
      })
      .then(isEqual => {
        if (!isEqual) {
          const error = new Error("Wrong password!")
          error.statusCode = 401
          throw error;
        }

        const token = jwt.sign(
          {
            email: loadedAdmin.email, 
            userId: loadedAdmin._id.toString()
          }, 'somesupersecretsecret', { expiresIn: '1h' })
        res.status(200).json({token: token, userId: loadedAdmin._id.toString()})
    })
    .catch(err => console.log(err))
})

mongoose
  .connect('mongodb+srv://nihad:2992nihat@cluster0.s3p6bd2.mongodb.net/?retryWrites=true&w=majority', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => {
    app.listen(8001, () => {
      console.log(`WAF server running on port 8001`);
    });
  })
  .catch((error) => {
    console.error('Error connecting to MongoDB:', error);
  });