require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');

const app = express();

// ================ SECURITY MIDDLEWARE ================
app.use(helmet({
  contentSecurityPolicy: false // We'll set custom CSP for frontend
}));

app.use(cors({
  origin: process.env.FRONTEND_URL || '*',
  credentials: true
}));

app.use(express.json());
app.use(express.static('public'));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use('/api/', limiter);

// ================ DATABASE SCHEMAS ================
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  credits: { type: Number, default: 0 },
  isAdmin: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now },
  lastLogin: { type: Date },
  isActive: { type: Boolean, default: true }
});

const configSchema = new mongoose.Schema({
  apiKey: { type: String, required: true },
  apiUrl: { type: String, default: 'https://relay-wzlz.onrender.com' },
  updatedAt: { type: Date, default: Date.now },
  updatedBy: { type: String }
});

const planSchema = new mongoose.Schema({
  name: { type: String, required: true },
  credits: { type: Number, required: true },
  price: { type: Number, required: true },
  isActive: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now }
});

const broadcastSchema = new mongoose.Schema({
  message: { type: String, required: true },
  type: { type: String, enum: ['info', 'warning', 'error', 'success'], default: 'info' },
  startTime: { type: Date, required: true },
  endTime: { type: Date, required: true },
  isActive: { type: Boolean, default: true },
  createdBy: { type: String },
  createdAt: { type: Date, default: Date.now }
});

const commandSchema = new mongoose.Schema({
  name: { type: String, required: true, unique: true },
  endpoint: { type: String, required: true },
  creditCost: { type: Number, default: 1 },
  isEnabled: { type: Boolean, default: true },
  description: { type: String }
});

const activityLogSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  username: { type: String },
  action: { type: String, required: true },
  commandType: { type: String },
  query: { type: String },
  creditsUsed: { type: Number },
  success: { type: Boolean },
  ipAddress: { type: String },
  userAgent: { type: String },
  timestamp: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const Config = mongoose.model('Config', configSchema);
const Plan = mongoose.model('Plan', planSchema);
const Broadcast = mongoose.model('Broadcast', broadcastSchema);
const Command = mongoose.model('Command', commandSchema);
const ActivityLog = mongoose.model('ActivityLog', activityLogSchema);

// ================ AUTHENTICATION MIDDLEWARE ================
const authMiddleware = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    
    if (!token) {
      return res.status(401).json({ 
        status: 'error', 
        message: 'Authentication required' 
      });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'darkboxes-secret-key-change-in-production');
    const user = await User.findById(decoded.userId);

    if (!user || !user.isActive) {
      return res.status(401).json({ 
        status: 'error', 
        message: 'Invalid or inactive account' 
      });
    }

    req.user = user;
    next();
  } catch (error) {
    return res.status(401).json({ 
      status: 'error', 
      message: 'Invalid token' 
    });
  }
};

const adminMiddleware = (req, res, next) => {
  if (!req.user.isAdmin) {
    return res.status(403).json({ 
      status: 'error', 
      message: 'Admin access required' 
    });
  }
  next();
};

// ================ LOGGING HELPER ================
const logActivity = async (data) => {
  try {
    await ActivityLog.create(data);
  } catch (error) {
    console.error('Failed to log activity:', error);
  }
};

// ================ AUTH ENDPOINTS ================
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;

    // Validation
    if (!username || !email || !password) {
      return res.status(400).json({ 
        status: 'error', 
        message: 'All fields are required' 
      });
    }

    if (password.length < 6) {
      return res.status(400).json({ 
        status: 'error', 
        message: 'Password must be at least 6 characters' 
      });
    }

    // Check existing user
    const existingUser = await User.findOne({ 
      $or: [{ username }, { email }] 
    });

    if (existingUser) {
      return res.status(400).json({ 
        status: 'error', 
        message: 'Username or email already exists' 
      });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user
    const user = await User.create({
      username,
      email,
      password: hashedPassword,
      credits: 10 // Welcome credits
    });

    await logActivity({
      userId: user._id,
      username: user.username,
      action: 'USER_REGISTERED',
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
      success: true
    });

    res.json({ 
      status: 'success', 
      message: 'Registration successful! 10 free credits added.',
      data: { 
        username: user.username,
        credits: user.credits 
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ 
      status: 'error', 
      message: 'Registration failed' 
    });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    const user = await User.findOne({ username });

    if (!user || !user.isActive) {
      return res.status(401).json({ 
        status: 'error', 
        message: 'Invalid credentials' 
      });
    }

    const validPassword = await bcrypt.compare(password, user.password);

    if (!validPassword) {
      return res.status(401).json({ 
        status: 'error', 
        message: 'Invalid credentials' 
      });
    }

    // Update last login
    user.lastLogin = new Date();
    await user.save();

    const token = jwt.sign(
      { userId: user._id, isAdmin: user.isAdmin },
      process.env.JWT_SECRET || 'darkboxes-secret-key-change-in-production',
      { expiresIn: '7d' }
    );

    await logActivity({
      userId: user._id,
      username: user.username,
      action: 'USER_LOGIN',
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
      success: true
    });

    res.json({ 
      status: 'success',
      data: {
        token,
        user: {
          username: user.username,
          email: user.email,
          credits: user.credits,
          isAdmin: user.isAdmin
        }
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ 
      status: 'error', 
      message: 'Login failed' 
    });
  }
});

// ================ USER ENDPOINTS ================
app.get('/api/user/profile', authMiddleware, async (req, res) => {
  res.json({ 
    status: 'success',
    data: {
      username: req.user.username,
      email: req.user.email,
      credits: req.user.credits,
      isAdmin: req.user.isAdmin,
      createdAt: req.user.createdAt
    }
  });
});

app.get('/api/user/balance', authMiddleware, async (req, res) => {
  res.json({ 
    status: 'success',
    data: {
      credits: req.user.credits
    }
  });
});

// ================ SEARCH ENDPOINTS ================
app.post('/api/search/:type', authMiddleware, async (req, res) => {
  try {
    const { type } = req.params;
    const { query } = req.body;

    // Check if command exists and is enabled
    const command = await Command.findOne({ name: type, isEnabled: true });
    
    if (!command) {
      return res.status(400).json({ 
        status: 'error', 
        message: 'Invalid or disabled command' 
      });
    }

    // Check credits
    if (req.user.credits < command.creditCost) {
      await logActivity({
        userId: req.user._id,
        username: req.user.username,
        action: 'SEARCH_FAILED',
        commandType: type,
        query,
        success: false,
        ipAddress: req.ip,
        userAgent: req.headers['user-agent']
      });

      return res.status(403).json({ 
        status: 'error', 
        message: 'Insufficient credits',
        data: { 
          required: command.creditCost,
          available: req.user.credits 
        }
      });
    }

    // Get API config
    const config = await Config.findOne().sort({ updatedAt: -1 });
    
    if (!config || !config.apiKey) {
      return res.status(500).json({ 
        status: 'error', 
        message: 'API not configured' 
      });
    }

    // Make API request
    try {
      const response = await axios.post(
        `${config.apiUrl}${command.endpoint}`,
        { query },
        {
          headers: {
            'X-API-Key': config.apiKey,
            'Content-Type': 'application/json'
          },
          timeout: 60000
        }
      );

      // Deduct credits
      req.user.credits -= command.creditCost;
      await req.user.save();

      await logActivity({
        userId: req.user._id,
        username: req.user.username,
        action: 'SEARCH_SUCCESS',
        commandType: type,
        query,
        creditsUsed: command.creditCost,
        success: true,
        ipAddress: req.ip,
        userAgent: req.headers['user-agent']
      });

      res.json({ 
        status: 'success',
        data: response.data,
        creditsRemaining: req.user.credits
      });
    } catch (apiError) {
      await logActivity({
        userId: req.user._id,
        username: req.user.username,
        action: 'SEARCH_FAILED',
        commandType: type,
        query,
        success: false,
        ipAddress: req.ip,
        userAgent: req.headers['user-agent']
      });

      res.status(500).json({ 
        status: 'error', 
        message: 'API request failed',
        error: apiError.response?.data || apiError.message
      });
    }
  } catch (error) {
    console.error('Search error:', error);
    res.status(500).json({ 
      status: 'error', 
      message: 'Search failed' 
    });
  }
});

// ================ PLANS ENDPOINTS ================
app.get('/api/plans', async (req, res) => {
  try {
    const plans = await Plan.find({ isActive: true }).sort({ price: 1 });
    res.json({ 
      status: 'success',
      data: plans
    });
  } catch (error) {
    res.status(500).json({ 
      status: 'error', 
      message: 'Failed to fetch plans' 
    });
  }
});

// ================ COMMANDS ENDPOINTS ================
app.get('/api/commands', authMiddleware, async (req, res) => {
  try {
    const commands = await Command.find({ isEnabled: true }).select('-__v');
    res.json({ 
      status: 'success',
      data: commands
    });
  } catch (error) {
    res.status(500).json({ 
      status: 'error', 
      message: 'Failed to fetch commands' 
    });
  }
});

// ================ BROADCAST ENDPOINTS ================
app.get('/api/broadcasts/active', async (req, res) => {
  try {
    const now = new Date();
    const broadcasts = await Broadcast.find({
      isActive: true,
      startTime: { $lte: now },
      endTime: { $gte: now }
    }).sort({ createdAt: -1 });

    res.json({ 
      status: 'success',
      data: broadcasts
    });
  } catch (error) {
    res.status(500).json({ 
      status: 'error', 
      message: 'Failed to fetch broadcasts' 
    });
  }
});

// ================ ADMIN ENDPOINTS ================
// Config Management
app.get('/api/admin/config', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const config = await Config.findOne().sort({ updatedAt: -1 });
    res.json({ 
      status: 'success',
      data: config || { apiKey: '', apiUrl: 'https://relay-wzlz.onrender.com' }
    });
  } catch (error) {
    res.status(500).json({ 
      status: 'error', 
      message: 'Failed to fetch config' 
    });
  }
});

app.post('/api/admin/config', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { apiKey, apiUrl } = req.body;

    await Config.deleteMany({}); // Keep only latest config
    const config = await Config.create({
      apiKey,
      apiUrl: apiUrl || 'https://relay-wzlz.onrender.com',
      updatedBy: req.user.username
    });

    await logActivity({
      userId: req.user._id,
      username: req.user.username,
      action: 'CONFIG_UPDATED',
      success: true,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent']
    });

    res.json({ 
      status: 'success',
      data: config
    });
  } catch (error) {
    res.status(500).json({ 
      status: 'error', 
      message: 'Failed to update config' 
    });
  }
});

// User Management
app.get('/api/admin/users', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const users = await User.find().select('-password').sort({ createdAt: -1 });
    res.json({ 
      status: 'success',
      data: users
    });
  } catch (error) {
    res.status(500).json({ 
      status: 'error', 
      message: 'Failed to fetch users' 
    });
  }
});

app.post('/api/admin/users/:userId/credits', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { userId } = req.params;
    const { credits } = req.body;

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ 
        status: 'error', 
        message: 'User not found' 
      });
    }

    user.credits = credits;
    await user.save();

    await logActivity({
      userId: req.user._id,
      username: req.user.username,
      action: 'CREDITS_UPDATED',
      query: `Set ${user.username} credits to ${credits}`,
      success: true,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent']
    });

    res.json({ 
      status: 'success',
      data: user
    });
  } catch (error) {
    res.status(500).json({ 
      status: 'error', 
      message: 'Failed to update credits' 
    });
  }
});

app.post('/api/admin/users/:userId/toggle', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { userId } = req.params;

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ 
        status: 'error', 
        message: 'User not found' 
      });
    }

    user.isActive = !user.isActive;
    await user.save();

    await logActivity({
      userId: req.user._id,
      username: req.user.username,
      action: 'USER_TOGGLED',
      query: `${user.isActive ? 'Activated' : 'Deactivated'} ${user.username}`,
      success: true,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent']
    });

    res.json({ 
      status: 'success',
      data: user
    });
  } catch (error) {
    res.status(500).json({ 
      status: 'error', 
      message: 'Failed to toggle user' 
    });
  }
});

// Plan Management
app.get('/api/admin/plans', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const plans = await Plan.find().sort({ price: 1 });
    res.json({ 
      status: 'success',
      data: plans
    });
  } catch (error) {
    res.status(500).json({ 
      status: 'error', 
      message: 'Failed to fetch plans' 
    });
  }
});

app.post('/api/admin/plans', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const plan = await Plan.create(req.body);

    await logActivity({
      userId: req.user._id,
      username: req.user.username,
      action: 'PLAN_CREATED',
      query: `Created plan: ${plan.name}`,
      success: true,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent']
    });

    res.json({ 
      status: 'success',
      data: plan
    });
  } catch (error) {
    res.status(500).json({ 
      status: 'error', 
      message: 'Failed to create plan' 
    });
  }
});

app.put('/api/admin/plans/:planId', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const plan = await Plan.findByIdAndUpdate(
      req.params.planId,
      req.body,
      { new: true }
    );

    await logActivity({
      userId: req.user._id,
      username: req.user.username,
      action: 'PLAN_UPDATED',
      query: `Updated plan: ${plan.name}`,
      success: true,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent']
    });

    res.json({ 
      status: 'success',
      data: plan
    });
  } catch (error) {
    res.status(500).json({ 
      status: 'error', 
      message: 'Failed to update plan' 
    });
  }
});

app.delete('/api/admin/plans/:planId', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const plan = await Plan.findByIdAndDelete(req.params.planId);

    await logActivity({
      userId: req.user._id,
      username: req.user.username,
      action: 'PLAN_DELETED',
      query: `Deleted plan: ${plan.name}`,
      success: true,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent']
    });

    res.json({ 
      status: 'success',
      message: 'Plan deleted'
    });
  } catch (error) {
    res.status(500).json({ 
      status: 'error', 
      message: 'Failed to delete plan' 
    });
  }
});

// Command Management
app.get('/api/admin/commands', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const commands = await Command.find().sort({ name: 1 });
    res.json({ 
      status: 'success',
      data: commands
    });
  } catch (error) {
    res.status(500).json({ 
      status: 'error', 
      message: 'Failed to fetch commands' 
    });
  }
});

app.post('/api/admin/commands', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const command = await Command.create(req.body);

    await logActivity({
      userId: req.user._id,
      username: req.user.username,
      action: 'COMMAND_CREATED',
      query: `Created command: ${command.name}`,
      success: true,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent']
    });

    res.json({ 
      status: 'success',
      data: command
    });
  } catch (error) {
    res.status(500).json({ 
      status: 'error', 
      message: 'Failed to create command' 
    });
  }
});

app.put('/api/admin/commands/:commandId', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const command = await Command.findByIdAndUpdate(
      req.params.commandId,
      req.body,
      { new: true }
    );

    await logActivity({
      userId: req.user._id,
      username: req.user.username,
      action: 'COMMAND_UPDATED',
      query: `Updated command: ${command.name}`,
      success: true,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent']
    });

    res.json({ 
      status: 'success',
      data: command
    });
  } catch (error) {
    res.status(500).json({ 
      status: 'error', 
      message: 'Failed to update command' 
    });
  }
});

app.delete('/api/admin/commands/:commandId', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const command = await Command.findByIdAndDelete(req.params.commandId);

    await logActivity({
      userId: req.user._id,
      username: req.user.username,
      action: 'COMMAND_DELETED',
      query: `Deleted command: ${command.name}`,
      success: true,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent']
    });

    res.json({ 
      status: 'success',
      message: 'Command deleted'
    });
  } catch (error) {
    res.status(500).json({ 
      status: 'error', 
      message: 'Failed to delete command' 
    });
  }
});

// Broadcast Management
app.get('/api/admin/broadcasts', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const broadcasts = await Broadcast.find().sort({ createdAt: -1 });
    res.json({ 
      status: 'success',
      data: broadcasts
    });
  } catch (error) {
    res.status(500).json({ 
      status: 'error', 
      message: 'Failed to fetch broadcasts' 
    });
  }
});

app.post('/api/admin/broadcasts', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const broadcast = await Broadcast.create({
      ...req.body,
      createdBy: req.user.username
    });

    await logActivity({
      userId: req.user._id,
      username: req.user.username,
      action: 'BROADCAST_CREATED',
      query: broadcast.message.substring(0, 100),
      success: true,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent']
    });

    res.json({ 
      status: 'success',
      data: broadcast
    });
  } catch (error) {
    res.status(500).json({ 
      status: 'error', 
      message: 'Failed to create broadcast' 
    });
  }
});

app.put('/api/admin/broadcasts/:broadcastId', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const broadcast = await Broadcast.findByIdAndUpdate(
      req.params.broadcastId,
      req.body,
      { new: true }
    );

    await logActivity({
      userId: req.user._id,
      username: req.user.username,
      action: 'BROADCAST_UPDATED',
      success: true,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent']
    });

    res.json({ 
      status: 'success',
      data: broadcast
    });
  } catch (error) {
    res.status(500).json({ 
      status: 'error', 
      message: 'Failed to update broadcast' 
    });
  }
});

app.delete('/api/admin/broadcasts/:broadcastId', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    await Broadcast.findByIdAndDelete(req.params.broadcastId);

    await logActivity({
      userId: req.user._id,
      username: req.user.username,
      action: 'BROADCAST_DELETED',
      success: true,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent']
    });

    res.json({ 
      status: 'success',
      message: 'Broadcast deleted'
    });
  } catch (error) {
    res.status(500).json({ 
      status: 'error', 
      message: 'Failed to delete broadcast' 
    });
  }
});

// Activity Logs
app.get('/api/admin/logs', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { page = 1, limit = 50 } = req.query;
    
    const logs = await ActivityLog.find()
      .sort({ timestamp: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit);
    
    const count = await ActivityLog.countDocuments();

    res.json({ 
      status: 'success',
      data: {
        logs,
        totalPages: Math.ceil(count / limit),
        currentPage: page
      }
    });
  } catch (error) {
    res.status(500).json({ 
      status: 'error', 
      message: 'Failed to fetch logs' 
    });
  }
});

// Dashboard Stats
app.get('/api/admin/stats', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const totalUsers = await User.countDocuments();
    const activeUsers = await User.countDocuments({ isActive: true });
    const totalSearches = await ActivityLog.countDocuments({ action: 'SEARCH_SUCCESS' });
    
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const todaySearches = await ActivityLog.countDocuments({ 
      action: 'SEARCH_SUCCESS',
      timestamp: { $gte: today }
    });

    const recentActivity = await ActivityLog.find()
      .sort({ timestamp: -1 })
      .limit(10);

    res.json({ 
      status: 'success',
      data: {
        totalUsers,
        activeUsers,
        totalSearches,
        todaySearches,
        recentActivity
      }
    });
  } catch (error) {
    res.status(500).json({ 
      status: 'error', 
      message: 'Failed to fetch stats' 
    });
  }
});

// ================ DATABASE INITIALIZATION ================
async function initializeDatabase() {
  try {
    // Create default commands if none exist
    const commandCount = await Command.countDocuments();
    if (commandCount === 0) {
      const defaultCommands = [
        { name: 'phone', endpoint: '/api/v1/search/phone', creditCost: 1, description: 'Search phone number information' },
        { name: 'family', endpoint: '/api/v1/search/family', creditCost: 2, description: 'Search family information' },
        { name: 'aadhar', endpoint: '/api/v1/search/aadhar', creditCost: 3, description: 'Search Aadhar card details' },
        { name: 'vehicle', endpoint: '/api/v1/search/vehicle', creditCost: 2, description: 'Search vehicle registration' },
        { name: 'upi', endpoint: '/api/v1/search/upi', creditCost: 1, description: 'Search UPI ID information' },
        { name: 'email', endpoint: '/api/v1/search/email', creditCost: 1, description: 'Search email information' },
        { name: 'telegram', endpoint: '/api/v1/search/telegram', creditCost: 1, description: 'Search Telegram username' },
        { name: 'imei', endpoint: '/api/v1/search/imei', creditCost: 2, description: 'Search IMEI number' },
        { name: 'gst', endpoint: '/api/v1/search/gst', creditCost: 2, description: 'Search GST number' },
        { name: 'instagram', endpoint: '/api/v1/search/instagram', creditCost: 1, description: 'Search Instagram username' },
        { name: 'pakistan', endpoint: '/api/v1/search/pakistan', creditCost: 2, description: 'Search Pakistan database' },
        { name: 'ip', endpoint: '/api/v1/search/ip', creditCost: 1, description: 'Search IP address information' },
        { name: 'ifsc', endpoint: '/api/v1/search/ifsc', creditCost: 1, description: 'Search IFSC code' },
        { name: 'leak', endpoint: '/api/v1/search/leak', creditCost: 3, description: 'Advanced OSINT search' }
      ];
      
      await Command.insertMany(defaultCommands);
      console.log('✓ Default commands created');
    }

    // Create default plans if none exist
    const planCount = await Plan.countDocuments();
    if (planCount === 0) {
      const defaultPlans = [
        { name: 'Starter', credits: 50, price: 100 },
        { name: 'Pro', credits: 150, price: 250 },
        { name: 'Elite', credits: 500, price: 750 },
        { name: 'Ultimate', credits: 1500, price: 2000 }
      ];
      
      await Plan.insertMany(defaultPlans);
      console.log('✓ Default plans created');
    }

    // Create admin user if none exists
    const adminExists = await User.findOne({ isAdmin: true });
    if (!adminExists) {
      const hashedPassword = await bcrypt.hash('admin123', 10);
      await User.create({
        username: 'admin',
        email: 'admin@darkboxes.com',
        password: hashedPassword,
        credits: 999999,
        isAdmin: true
      });
      console.log('✓ Admin user created (username: admin, password: admin123)');
    }

    console.log('✓ Database initialized successfully');
  } catch (error) {
    console.error('Database initialization error:', error);
  }
}

// ================ SERVER START ================
const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/darkboxes';

mongoose.connect(MONGODB_URI)
  .then(async () => {
    console.log('✓ Connected to MongoDB');
    await initializeDatabase();
    
    app.listen(PORT, () => {
      console.log(`✓ Server running on port ${PORT}`);
      console.log(`✓ Frontend: http://localhost:${PORT}`);
      console.log(`✓ API: http://localhost:${PORT}/api`);
    });
  })
  .catch((error) => {
    console.error('MongoDB connection error:', error);
    process.exit(1);
  });
