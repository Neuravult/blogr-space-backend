// core-requirements.js
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const path = require('path');
const { body, validationResult } = require('express-validator');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const redis = require('redis');
const session = require('express-session');
const RedisStore = require('connect-redis')(session);
const morgan = require('morgan');
const swaggerUi = require('swagger-ui-express');
const YAML = require('yamljs');
const cron = require('node-cron');
const aws = require('aws-sdk');

// Initialize Express
const app = express();

// ======================
// 1. INFRASTRUCTURE SETUP
// ======================

// Redis Configuration
const redisClient = redis.createClient({
  url: process.env.REDIS_URL,
  legacyMode: true
});
redisClient.connect().catch(console.error);

// AWS Configuration
aws.config.update({
  region: process.env.AWS_REGION,
  accessKeyId: process.env.AWS_ACCESS_KEY,
  secretAccessKey: process.env.AWS_SECRET_KEY
});
const s3 = new aws.S3();
const cloudfront = new aws.CloudFront();

// ======================
// 2. SECURITY MIDDLEWARE
// ======================

// Enhanced Helmet Configuration
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "cdn.example.com"],
      styleSrc: ["'self'", "'unsafe-inline'", "fonts.googleapis.com"],
      fontSrc: ["'self'", "fonts.gstatic.com"],
      imgSrc: ["'self'", "data:", "cdn.example.com"],
      connectSrc: ["'self'", process.env.FRONTEND_URL]
    }
  },
  crossOriginEmbedderPolicy: false,
  hsts: { maxAge: 31536000, includeSubDomains: true }
}));

// Rate Limiting
const adaptiveRateLimiter = (defaultWindow, defaultMax) => {
  return async (req, res, next) => {
    const clientKey = req.ip || req.headers['x-client-id'];
    const abuseRisk = await redisClient.get(`risk:${clientKey}`);
    
    const windowMs = abuseRisk ? defaultWindow / 2 : defaultWindow;
    const max = abuseRisk ? defaultMax / 3 : defaultMax;
    
    return rateLimit({ windowMs, max })(req, res, next);
  };
};

app.use('/api/', adaptiveRateLimiter(15*60*1000, 500));
app.use('/api/auth/', adaptiveRateLimiter(15*60*1000, 20));

// Session Management
app.use(session({
  store: new RedisStore({ client: redisClient }),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000
  }
}));

// ======================
// 3. DATABASE MODELS
// ======================

// MongoDB Connection
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  minPoolSize: 10,
  maxPoolSize: 100,
  serverSelectionTimeoutMS: 5000,
  socketTimeoutMS: 45000,
  shardKey: { 
    'meta.region': 1,
    createdAt: 1 
  }
}).then(() => console.log('MongoDB Connected'))
  .catch(err => console.error('MongoDB Connection Error:', err));

// User Schema
const UserSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  bio: { type: String, default: '' },
  website: { type: String, default: '' },
  profilePhoto: { type: String, default: '' },
  isAdmin: { type: Boolean, default: false },
  stripeAccountId: { type: String },
  meta: {
    region: { type: String, default: 'global' },
    riskScore: { type: Number, default: 0 }
  },
  monetization: {
    adsEnabled: { type: Boolean, default: false },
    tipsEnabled: { type: Boolean, default: false },
    premiumEnabled: { type: Boolean, default: false },
    adsPending: { type: Boolean, default: false }
  },
  subscription: {
    tier: { type: String, enum: ['basic', 'premium', 'pro'] },
    status: { type: String, default: 'inactive' },
    startedAt: { type: Date },
    expiresAt: { type: Date }
  },
  refreshTokens: [String],
  followers: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  following: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  createdAt: { type: Date, default: Date.now },
  lastActive: { type: Date, default: Date.now }
}, { autoIndex: true });

UserSchema.index({ email: 1 }, { unique: true });
UserSchema.index({ lastActive: -1 });

// Post Schema
const PostSchema = new mongoose.Schema({
  title: { type: String, required: true },
  content: { type: String, required: true },
  author: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  tags: [{ type: String }],
  isPublished: { type: Boolean, default: false },
  publishedAt: { type: Date },
  views: { type: Number, default: 0 },
  likes: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  comments: [{
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    text: { type: String, required: true },
    createdAt: { type: Date, default: Date.now }
  }],
  monetization: {
    adRevenue: { type: Number, default: 0 },
    tips: { type: Number, default: 0 }
  }
}, { autoIndex: true, timestamps: true });

PostSchema.index({ author: 1, publishedAt: -1 });
PostSchema.index({ tags: 1 });

// Earning Schema
const EarningSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  amount: { type: Number, required: true },
  source: { type: String, enum: ['ad', 'tip', 'subscription', 'sponsorship'], required: true },
  post: { type: mongoose.Schema.Types.ObjectId, ref: 'Post' },
  paidOut: { type: Boolean, default: false },
  paidAt: { type: Date },
  timestamp: { type: Date, default: Date.now }
}, { timestamps: true });

EarningSchema.index({ user: 1, timestamp: -1 });

// Refresh Token Schema
const RefreshTokenSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  token: { type: String, required: true },
  expires: { type: Date, required: true },
  revoked: { type: Date }
});

// Compile Models
const User = mongoose.model('User', UserSchema);
const Post = mongoose.model('Post', PostSchema);
const Earning = mongoose.model('Earning', EarningSchema);
const RefreshToken = mongoose.model('RefreshToken', RefreshTokenSchema);

// ======================
// 4. CORE MIDDLEWARE
// ======================

// Request Logging
app.use(morgan(process.env.NODE_ENV === 'production' ? 'combined' : 'dev'));

// API Documentation
const swaggerDocument = YAML.load('./swagger.yaml');
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument));

// CDN Static Assets
app.use('/static', express.static('public', {
  setHeaders: (res, path) => {
    if (path.endsWith('.js') || path.endsWith('.css')) {
      res.set('Cache-Control', 'public, max-age=31536000, immutable');
    }
  }
}));

// Body Parsing
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// CORS Configuration
app.use(cors({
  origin: process.env.FRONTEND_URL,
  credentials: true
}));

// ======================
// 5. UTILITY FUNCTIONS
// ======================

// Payment Processor
const processPayment = async (amount, source) => {
  try {
    const payment = await stripe.paymentIntents.create({
      amount: amount * 100,
      currency: 'usd',
      payment_method: source,
      confirm: true,
      return_url: `${process.env.FRONTEND_URL}/payment/success`
    });
    return payment.status === 'succeeded';
  } catch (error) {
    console.error('Payment processing error:', error);
    return false;
  }
};

// Fraud Detection
const analyzeRisk = async (req) => {
  const riskFactors = {
    ip: req.ip,
    userAgent: req.headers['user-agent'],
    velocity: await redisClient.get(`req_count:${req.ip}`)
  };
  
  // Simplified risk scoring (0-1)
  return riskFactors.velocity > 100 ? 0.85 : 0.15;
};

// ======================
// 6. ROUTE HANDLERS
// ======================

// Authentication Routes
app.post('/api/auth/login', [
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 8 })
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  try {
    const user = await User.findOne({ email: req.body.email });
    if (!user || !(await user.matchPassword(req.body.password))) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Risk analysis
    const riskScore = await analyzeRisk(req);
    if (riskScore > 0.8) {
      await redisClient.setEx(`risk:${req.ip}`, 3600, 'high');
      return res.status(429).json({ message: 'Account review required' });
    }

    // Token generation
    const accessToken = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '15m' });
    const refreshToken = jwt.sign({ userId: user._id }, process.env.REFRESH_SECRET, { expiresIn: '7d' });

    // Store refresh token
    await RefreshToken.create({
      user: user._id,
      token: refreshToken,
      expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
    });

    // Set cookies
    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    res.json({
      _id: user._id,
      name: user.name,
      email: user.email,
      isAdmin: user.isAdmin,
      accessToken
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// [Additional routes for signup, logout, refresh tokens, password reset...]

// Content Routes
app.get('/api/posts', cacheMiddleware(300), async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    const posts = await Post.find({ isPublished: true })
      .populate('author', 'name profilePhoto')
      .sort({ publishedAt: -1 })
      .skip(skip)
      .limit(limit);

    const totalPosts = await Post.countDocuments({ isPublished: true });

    res.json({
      posts,
      currentPage: page,
      totalPages: Math.ceil(totalPosts / limit)
    });
  } catch (error) {
    console.error('Get posts error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// [Additional routes for post creation, updates, comments...]

// Monetization Routes
app.post('/api/monetization/subscribe', authMiddleware, [
  body('tier').isIn(['basic', 'premium', 'pro']),
  body('paymentSource').isString().notEmpty()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const { tier, paymentSource } = req.body;
  const tierPrices = { basic: 499, premium: 999, pro: 1499 };

  try {
    const paymentSuccess = await processPayment(tierPrices[tier], paymentSource);
    if (!paymentSuccess) return res.status(402).json({ message: 'Payment failed' });

    await User.findByIdAndUpdate(req.user._id, {
      subscription: {
        tier,
        status: 'active',
        startedAt: new Date(),
        expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)
      }
    });

    await Earning.create({
      user: req.user._id,
      amount: tierPrices[tier],
      source: 'subscription'
    });

    res.json({ message: `Subscribed to ${tier} tier successfully` });
  } catch (error) {
    console.error('Subscription error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// [Additional routes for tips, ads, payouts...]

// ======================
// 7. CRON JOBS
// ======================

// Weekly payout scheduler
cron.schedule('0 0 * * MON', async () => {
  const pendingPayouts = await Earning.aggregate([
    { $match: { paidOut: false, amount: { $gt: 50 } },
    { $group: { _id: "$user", total: { $sum: "$amount" } } }
  ]);
  
  for (const payout of pendingPayouts) {
    const user = await User.findById(payout._id);
    if (!user.stripeAccountId) continue;

    await stripe.transfers.create({
      amount: payout.total * 100,
      currency: 'usd',
      destination: user.stripeAccountId,
      description: 'Weekly content earnings payout'
    });
    
    await Earning.updateMany(
      { user: payout._id, paidOut: false },
      { $set: { paidOut: true, paidAt: new Date() } }
    );
  }
});

// ======================
// 8. ERROR HANDLING
// ======================

app.use((err, req, res, next) => {
  console.error(err.stack);
  
  // Specific error handling
  if (err.type === 'StripeCardError') {
    return res.status(402).json({ message: err.message });
  }
  
  if (err.name === 'ValidationError') {
    return res.status(400).json({ message: err.message });
  }
  
  // Default error handler
  res.status(500).json({ message: 'Internal server error' });
});

// ======================
// 9. SERVER INITIALIZATION
// ======================

const PORT = process.env.PORT || 5000;

if (process.env.NODE_ENV === 'production') {
  const cluster = require('cluster');
  const numCPUs = require('os').cpus().length;
  
  if (cluster.isPrimary) {
    console.log(`Master ${process.pid} is running`);
    
    // Fork workers
    for (let i = 0; i < numCPUs; i++) {
      cluster.fork();
    }
    
    cluster.on('exit', (worker) => {
      console.log(`Worker ${worker.process.pid} died`);
      cluster.fork();
    });
  } else {
    app.listen(PORT, () => {
      console.log(`Worker ${process.pid} started on port ${PORT}`);
    });
  }
} else {
  app.listen(PORT, () => {
    console.log(`Server running in development mode on port ${PORT}`);
  });
}