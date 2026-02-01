const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcryptjs');
const axios = require('axios');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors({
    origin: process.env.FRONTEND_URL || 'http://localhost:3000',
    credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// File upload configuration
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const uploadDir = './uploads/qr-codes';
        if (!fs.existsSync(uploadDir)) {
            fs.mkdirSync(uploadDir, { recursive: true });
        }
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + '-' + file.originalname);
    }
});
const upload = multer({ storage });

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => {
    console.log('✅ MongoDB Connected');
}).catch(err => {
    console.error('❌ MongoDB Connection Error:', err);
});

// Session configuration
app.use(session({
    secret: process.env.SESSION_SECRET || 'your-secret-key-change-this',
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
        mongoUrl: process.env.MONGODB_URI,
        ttl: 24 * 60 * 60 // 1 day
    }),
    cookie: {
        maxAge: 24 * 60 * 60 * 1000, // 1 day
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production'
    }
}));

// Mongoose Schemas
const userSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    name: String,
    credits: { type: Number, default: 0 },
    totalSpent: { type: Number, default: 0 },
    isAdmin: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now },
    lastLogin: { type: Date, default: Date.now }
});

const planSchema = new mongoose.Schema({
    name: String,
    credits: Number,
    price: Number,
    popular: { type: Boolean, default: false },
    features: [String],
    isActive: { type: Boolean, default: true },
    createdAt: { type: Date, default: Date.now }
});

const paymentSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    planId: { type: mongoose.Schema.Types.ObjectId, ref: 'Plan' },
    amount: Number,
    credits: Number,
    status: { type: String, enum: ['pending', 'completed', 'rejected'], default: 'pending' },
    transactionId: String,
    screenshot: String,
    createdAt: { type: Date, default: Date.now },
    completedAt: Date
});

const searchHistorySchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    query: String,
    searchType: String,
    creditsUsed: { type: Number, default: 1 },
    result: mongoose.Schema.Types.Mixed,
    status: { type: String, enum: ['success', 'failed', 'processing'], default: 'processing' },
    createdAt: { type: Date, default: Date.now }
});

const settingsSchema = new mongoose.Schema({
    key: { type: String, unique: true },
    value: mongoose.Schema.Types.Mixed,
    updatedAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const Plan = mongoose.model('Plan', planSchema);
const Payment = mongoose.model('Payment', paymentSchema);
const SearchHistory = mongoose.model('SearchHistory', searchHistorySchema);
const Settings = mongoose.model('Settings', settingsSchema);

// Middleware to check authentication
const isAuthenticated = (req, res, next) => {
    if (req.session && req.session.userId) {
        return next();
    }
    res.status(401).json({ error: 'Not authenticated' });
};

// Middleware to check admin
const isAdmin = async (req, res, next) => {
    if (req.session && req.session.userId) {
        const user = await User.findById(req.session.userId);
        if (user && user.isAdmin) {
            return next();
        }
    }
    res.status(403).json({ error: 'Admin access required' });
};

// Helper function to get settings
async function getSetting(key, defaultValue = null) {
    const setting = await Settings.findOne({ key });
    return setting ? setting.value : defaultValue;
}

async function setSetting(key, value) {
    await Settings.findOneAndUpdate(
        { key },
        { key, value, updatedAt: new Date() },
        { upsert: true }
    );
}

// =================== AUTH ROUTES ===================

// Register
app.post('/auth/register', async (req, res) => {
    try {
        const { email, password, name } = req.body;

        if (!email || !password || !name) {
            return res.status(400).json({ error: 'All fields required' });
        }

        // Check if user exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ error: 'Email already registered' });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create user
        const user = await User.create({
            email,
            password: hashedPassword,
            name,
            credits: 0
        });

        // Create session
        req.session.userId = user._id;

        res.json({
            id: user._id,
            name: user.name,
            email: user.email,
            credits: user.credits,
            isAdmin: user.isAdmin
        });
    } catch (error) {
        console.error('Register error:', error);
        res.status(500).json({ error: 'Registration failed' });
    }
});

// Login
app.post('/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password required' });
        }

        // Find user
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Check password
        const isValid = await bcrypt.compare(password, user.password);
        if (!isValid) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Update last login
        user.lastLogin = new Date();
        await user.save();

        // Create session
        req.session.userId = user._id;

        res.json({
            id: user._id,
            name: user.name,
            email: user.email,
            credits: user.credits,
            isAdmin: user.isAdmin
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

app.get('/auth/user', isAuthenticated, async (req, res) => {
    try {
        const user = await User.findById(req.session.userId).select('-password');
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        res.json({
            id: user._id,
            name: user.name,
            email: user.email,
            credits: user.credits,
            isAdmin: user.isAdmin
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to get user' });
    }
});

app.post('/auth/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).json({ error: 'Logout failed' });
        }
        res.json({ success: true });
    });
});

// =================== PLAN ROUTES ===================

app.get('/api/plans', async (req, res) => {
    try {
        const plans = await Plan.find({ isActive: true }).sort({ price: 1 });
        res.json(plans);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// =================== PAYMENT ROUTES ===================

app.post('/api/payment/initiate', isAuthenticated, async (req, res) => {
    try {
        const { planId } = req.body;
        const plan = await Plan.findById(planId);
        
        if (!plan) {
            return res.status(404).json({ error: 'Plan not found' });
        }

        const user = await User.findById(req.session.userId);
        
        const payment = await Payment.create({
            userId: user._id,
            planId: plan._id,
            amount: plan.price,
            credits: plan.credits,
            status: 'pending'
        });

        // Get payment settings
        const upiId = await getSetting('upi_id', 'your-upi@bank');
        const qrCode = await getSetting('qr_code', '/uploads/qr-codes/default-qr.png');

        res.json({
            paymentId: payment._id,
            plan: {
                name: plan.name,
                price: plan.price,
                credits: plan.credits
            },
            upiId,
            qrCode
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/payment/status/:paymentId', isAuthenticated, async (req, res) => {
    try {
        const user = await User.findById(req.session.userId);
        
        const payment = await Payment.findOne({
            _id: req.params.paymentId,
            userId: user._id
        }).populate('planId');

        if (!payment) {
            return res.status(404).json({ error: 'Payment not found' });
        }

        res.json({
            status: payment.status,
            amount: payment.amount,
            credits: payment.credits,
            plan: payment.planId
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/payment/history', isAuthenticated, async (req, res) => {
    try {
        const user = await User.findById(req.session.userId);
        
        const payments = await Payment.find({ userId: user._id })
            .populate('planId')
            .sort({ createdAt: -1 })
            .limit(20);
        
        res.json(payments);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// =================== SEARCH ROUTES ===================

app.post('/api/search', isAuthenticated, async (req, res) => {
    try {
        const { query, searchType } = req.body;

        if (!query || !searchType) {
            return res.status(400).json({ error: 'Query and searchType required' });
        }

        // Get user
        const user = await User.findById(req.session.userId);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Check if user has credits
        if (user.credits < 1) {
            return res.status(403).json({ 
                error: 'Insufficient credits',
                credits: user.credits
            });
        }

        // Create search history entry
        const searchHistory = await SearchHistory.create({
            userId: user._id,
            query,
            searchType,
            creditsUsed: 1,
            status: 'processing'
        });

        // Deduct credit
        user.credits -= 1;
        await user.save();

        // Call the Python bot API
        try {
            const botApiUrl = process.env.BOT_API_URL || 'http://localhost:8000';
            const response = await axios.post(`${botApiUrl}/api/v1/search`, {
                query,
                type: searchType
            }, {
                timeout: 60000 // 60 seconds timeout
            });

            // Update search history with result
            searchHistory.result = response.data;
            searchHistory.status = 'success';
            await searchHistory.save();

            res.json({
                success: true,
                data: response.data,
                creditsRemaining: user.credits
            });

        } catch (apiError) {
            console.error('Bot API Error:', apiError.message);
            
            // Refund credit on API failure
            user.credits += 1;
            await user.save();

            searchHistory.status = 'failed';
            searchHistory.result = { error: apiError.message };
            await searchHistory.save();

            res.status(500).json({ 
                error: 'Search failed. Credit refunded.',
                details: apiError.message
            });
        }

    } catch (error) {
        console.error('Search Error:', error);
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/search/history', isAuthenticated, async (req, res) => {
    try {
        const user = await User.findById(req.session.userId);
        
        const history = await SearchHistory.find({ userId: user._id })
            .sort({ createdAt: -1 })
            .limit(50);
        
        res.json(history);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// =================== ADMIN ROUTES ===================

// Get all users
app.get('/api/admin/users', isAdmin, async (req, res) => {
    try {
        const users = await User.find().select('-googleId').sort({ createdAt: -1 });
        res.json(users);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Add credits to user
app.post('/api/admin/users/:userId/credits', isAdmin, async (req, res) => {
    try {
        const { credits } = req.body;
        const user = await User.findById(req.params.userId);
        
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        user.credits += parseInt(credits);
        await user.save();

        res.json({ success: true, newCredits: user.credits });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get all plans (including inactive)
app.get('/api/admin/plans', isAdmin, async (req, res) => {
    try {
        const plans = await Plan.find().sort({ price: 1 });
        res.json(plans);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Create plan
app.post('/api/admin/plans', isAdmin, async (req, res) => {
    try {
        const plan = await Plan.create(req.body);
        res.json(plan);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Update plan
app.put('/api/admin/plans/:planId', isAdmin, async (req, res) => {
    try {
        const plan = await Plan.findByIdAndUpdate(
            req.params.planId,
            req.body,
            { new: true }
        );
        res.json(plan);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Delete plan
app.delete('/api/admin/plans/:planId', isAdmin, async (req, res) => {
    try {
        await Plan.findByIdAndDelete(req.params.planId);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get pending payments
app.get('/api/admin/payments/pending', isAdmin, async (req, res) => {
    try {
        const payments = await Payment.find({ status: 'pending' })
            .populate('userId planId')
            .sort({ createdAt: -1 });
        res.json(payments);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Approve payment
app.post('/api/admin/payments/:paymentId/approve', isAdmin, async (req, res) => {
    try {
        const payment = await Payment.findById(req.params.paymentId).populate('userId');
        
        if (!payment) {
            return res.status(404).json({ error: 'Payment not found' });
        }

        if (payment.status !== 'pending') {
            return res.status(400).json({ error: 'Payment already processed' });
        }

        // Add credits to user
        const user = await User.findById(payment.userId);
        user.credits += payment.credits;
        user.totalSpent += payment.amount;
        await user.save();

        // Update payment status
        payment.status = 'completed';
        payment.completedAt = new Date();
        await payment.save();

        res.json({ success: true, user: { credits: user.credits } });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Reject payment
app.post('/api/admin/payments/:paymentId/reject', isAdmin, async (req, res) => {
    try {
        const payment = await Payment.findById(req.params.paymentId);
        
        if (!payment) {
            return res.status(404).json({ error: 'Payment not found' });
        }

        payment.status = 'rejected';
        await payment.save();

        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get settings
app.get('/api/admin/settings', isAdmin, async (req, res) => {
    try {
        const upiId = await getSetting('upi_id', '');
        const qrCode = await getSetting('qr_code', '');
        
        res.json({ upiId, qrCode });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Update UPI ID
app.post('/api/admin/settings/upi', isAdmin, async (req, res) => {
    try {
        const { upiId } = req.body;
        await setSetting('upi_id', upiId);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Upload QR Code
app.post('/api/admin/settings/qr', isAdmin, upload.single('qrCode'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }

        const qrPath = `/uploads/qr-codes/${req.file.filename}`;
        await setSetting('qr_code', qrPath);
        
        res.json({ success: true, path: qrPath });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Dashboard stats
app.get('/api/admin/stats', isAdmin, async (req, res) => {
    try {
        const totalUsers = await User.countDocuments();
        const totalRevenue = await Payment.aggregate([
            { $match: { status: 'completed' } },
            { $group: { _id: null, total: { $sum: '$amount' } } }
        ]);
        const pendingPayments = await Payment.countDocuments({ status: 'pending' });
        const totalSearches = await SearchHistory.countDocuments();

        res.json({
            totalUsers,
            totalRevenue: totalRevenue[0]?.total || 0,
            pendingPayments,
            totalSearches
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Serve uploaded files
app.use('/uploads', express.static('uploads'));

// =================== INITIALIZE DEFAULT DATA ===================

async function initializeDefaultData() {
    try {
        // Check if plans exist
        const planCount = await Plan.countDocuments();
        if (planCount === 0) {
            await Plan.insertMany([
                {
                    name: 'Starter',
                    credits: 10,
                    price: 99,
                    popular: false,
                    features: ['10 Searches', 'Basic Support', 'Valid for 30 days']
                },
                {
                    name: 'Professional',
                    credits: 50,
                    price: 399,
                    popular: true,
                    features: ['50 Searches', 'Priority Support', 'Valid for 60 days', 'Advanced Search Types']
                },
                {
                    name: 'Enterprise',
                    credits: 200,
                    price: 1299,
                    popular: false,
                    features: ['200 Searches', '24/7 Premium Support', 'Valid for 90 days', 'All Search Types', 'Dedicated Account Manager']
                }
            ]);
            console.log('✅ Default plans created');
        }

        // Set default UPI if not set
        const upiId = await getSetting('upi_id');
        if (!upiId) {
            await setSetting('upi_id', 'yourname@upi');
            console.log('✅ Default UPI ID set');
        }
    } catch (error) {
        console.error('❌ Error initializing default data:', error);
    }
}

// =================== START SERVER ===================

const PORT = process.env.PORT || 5000;

app.listen(PORT, async () => {
    console.log(`🚀 Server running on port ${PORT}`);
    await initializeDefaultData();
});
