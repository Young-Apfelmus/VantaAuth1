require('dotenv').config(); 
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const mongoose = require('mongoose');
const axios = require('axios'); 

const app = express();
const PORT = process.env.PORT || 3000;

// --- CONFIGURATION ---
const MONGO_URI = process.env.MONGO_URI;
const DISCORD_CLIENT_ID = "1459637612246597916";
const DISCORD_CLIENT_SECRET = "y3EwGJXiKnlBM9i-Zh-4goite4-FtGjD";
const DISCORD_REDIRECT_URI = "https://vantaauth1.onrender.com/auth/discord/callback";
const FRONTEND_URL = "https://vantaauth.xyz";

// --- DATABASE CONNECTION ---
if (!MONGO_URI) {
    console.error("FATAL: MONGO_URI is missing in Environment Variables!");
} else {
    mongoose.connect(MONGO_URI)
        .then(() => {
            console.log("✅ Connected to MongoDB");
            createOwnerAccount(); // Ensure Owner exists
        })
        .catch(err => console.error("❌ MongoDB Connection Error:", err));
}

app.use(cors());
app.use(bodyParser.json());

// --- HELPER: GET CLEAN IP ---
function getClientIp(req) {
    const forwarded = req.headers['x-forwarded-for'];
    if (forwarded) {
        return forwarded.split(',')[0].trim();
    }
    return req.socket.remoteAddress;
}

// --- DATABASE SCHEMAS ---

const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    discordId: { type: String, required: false }, // Not required for Owner
    knownIps: { type: [String], default: [] },
    // New Fields
    isPremium: { type: Boolean, default: false },
    premiumExpiresAt: { type: Date, default: null },
    createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model('User', UserSchema);

const AppSchema = new mongoose.Schema({
    id: { type: String, unique: true },
    name: String,
    owner: String,
    secret: String,
    totalUsers: { type: Number, default: 0 },
    onlineUsers: { type: Number, default: 0 }
});
const AppModel = mongoose.model('App', AppSchema);

const KeySchema = new mongoose.Schema({
    key: { type: String, unique: true },
    appId: String,
    appName: String,
    generatedBy: String,
    hwid: { type: String, default: null },
    ip: { type: String, default: null },
    active: { type: Boolean, default: true },
    expiresAt: { type: Date, default: null }, 
    durationLabel: { type: String, default: "Lifetime" },
    createdAt: { type: Date, default: Date.now }
});
const KeyModel = mongoose.model('Key', KeySchema);

const LogSchema = new mongoose.Schema({
    time: String,
    owner: String,
    appId: String, 
    appName: String,
    key: String,   
    ip: String,
    message: String,
    type: { type: String, default: "auth" }, 
    createdAt: { type: Date, default: Date.now }
});
const LogModel = mongoose.model('Log', LogSchema);

const ScriptSchema = new mongoose.Schema({
    owner: String,
    filename: { type: String, unique: true }, 
    userLabel: String, 
    content: String,
    createdAt: { type: Date, default: Date.now }
});
const ScriptModel = mongoose.model('Script', ScriptSchema);

const BlacklistSchema = new mongoose.Schema({
    ip: { type: String, required: true, unique: true },
    reason: String,
    expiresAt: { type: Date, default: null }, 
    createdAt: { type: Date, default: Date.now }
});
const BlacklistModel = mongoose.model('Blacklist', BlacklistSchema);


// --- HELPER FUNCTIONS ---
function generateId(len) { return crypto.randomBytes(len).toString('hex').slice(0, len); }
function getTime() { return new Date().toISOString().replace('T', ' ').substring(0, 19); }

function calculateExpiry(type, customDays) {
    const now = new Date();
    if (type === 'lifetime') return null;
    let daysToAdd = 0;
    if (type === '1d') daysToAdd = 1;
    else if (type === '3d') daysToAdd = 3;
    else if (type === '1w') daysToAdd = 7;
    else if (type === '1m') daysToAdd = 30;
    else if (type === '1y') daysToAdd = 365;
    else if (type === '5y') daysToAdd = 365 * 5;
    else if (type === 'custom') daysToAdd = parseInt(customDays) || 0;
    if (daysToAdd === 0) return null; 
    const expiryDate = new Date(now);
    expiryDate.setDate(expiryDate.getDate() + daysToAdd);
    return expiryDate;
}

async function isBlacklisted(ip) {
    const entry = await BlacklistModel.findOne({ ip });
    if (!entry) return false;
    if (entry.expiresAt && new Date() > entry.expiresAt) {
        await BlacklistModel.deleteOne({ ip });
        return false;
    }
    return true;
}

// --- OWNER SEED ---
async function createOwnerAccount() {
    try {
        const owner = await User.findOne({ username: "Owner" });
        if (!owner) {
            const hashedPassword = await bcrypt.hash("Owner", 10);
            await User.create({
                username: "Owner",
                password: hashedPassword,
                discordId: "OWNER-SYSTEM",
                isPremium: true
            });
            console.log("👑 Owner Account Created (User: Owner / Pass: Owner)");
        }
    } catch (e) { console.error("Owner Seed Error", e); }
}

// --- DISCORD OAUTH2 HANDLER ---
app.get('/auth/discord/url', (req, res) => {
    const url = `https://discord.com/api/oauth2/authorize?client_id=${DISCORD_CLIENT_ID}&redirect_uri=${encodeURIComponent(DISCORD_REDIRECT_URI)}&response_type=code&scope=identify`;
    res.json({ url });
});

app.get('/auth/discord/callback', async (req, res) => {
    const { code } = req.query;
    if (!code) return res.send("No code provided.");

    try {
        const tokenResponse = await axios.post(
            'https://discord.com/api/oauth2/token',
            new URLSearchParams({
                client_id: DISCORD_CLIENT_ID,
                client_secret: DISCORD_CLIENT_SECRET,
                grant_type: 'authorization_code',
                code,
                redirect_uri: DISCORD_REDIRECT_URI
            }),
            { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
        );

        const accessToken = tokenResponse.data.access_token;
        const userResponse = await axios.get('https://discord.com/api/users/@me', {
            headers: { Authorization: `Bearer ${accessToken}` }
        });

        const discordUser = userResponse.data;
        
        const payload = Buffer.from(JSON.stringify({
            id: discordUser.id,
            username: discordUser.username
        })).toString('base64');

        res.redirect(`${FRONTEND_URL}?discord_auth=${payload}`);

    } catch (e) {
        console.error("Discord Auth Error:", e.response ? e.response.data : e.message);
        res.send("Authentication Failed. Please try again.");
    }
});


// --- AUTHENTICATION ---

app.post('/api/register', async (req, res) => {
    try {
        const { username, password, discordId } = req.body;
        const ip = getClientIp(req); 

        if (!discordId) return res.json({ success: false, message: "Discord Verification Missing" });

        const existingUser = await User.findOne({ username });
        if (existingUser) return res.json({ success: false, message: "Username Taken" });
        
        const existingDiscord = await User.findOne({ discordId });
        if (existingDiscord) return res.json({ success: false, message: "Discord Account already linked to a user" });

        const hashedPassword = await bcrypt.hash(password, 10);
        
        const newUser = new User({ 
            username, 
            password: hashedPassword,
            discordId: discordId,
            knownIps: [ip] 
        });
        
        await newUser.save();
        res.json({ success: true, username: username, isPremium: false, premiumExpiresAt: null });
    } catch (e) {
        console.error(e);
        res.status(500).json({ success: false, message: "Server Error" });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { username, password, verificationDiscordId } = req.body;
        const ip = getClientIp(req); 

        const user = await User.findOne({ username });
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.json({ success: false, message: "Invalid Credentials" });
        }

        // Special bypass for Owner
        if (username === "Owner") {
             // Always update owner IP
             if(!user.knownIps.includes(ip)) {
                 user.knownIps.push(ip);
                 await user.save();
             }
             return res.json({ 
                 success: true, 
                 username: "Owner", 
                 isOwner: true,
                 isPremium: true,
                 premiumExpiresAt: null
             });
        }

        // IP CHECK LOGIC
        const isKnownIp = user.knownIps.includes(ip);

        if (!isKnownIp) {
            if (verificationDiscordId) {
                if (verificationDiscordId === user.discordId) {
                    user.knownIps.push(ip);
                    await user.save();
                } else {
                    return res.json({ success: false, message: "Wrong Discord Account! Use the one linked to this user." });
                }
            } else {
                return res.json({ success: false, requireVerification: true, message: "New IP detected. Please verify with Discord." });
            }
        }

        // Check Premium Expiry
        if (user.isPremium && user.premiumExpiresAt) {
            if (new Date() > new Date(user.premiumExpiresAt)) {
                user.isPremium = false;
                user.premiumExpiresAt = null;
                await user.save();
            }
        }

        res.json({ 
            success: true, 
            username: user.username,
            isOwner: false,
            isPremium: user.isPremium,
            premiumExpiresAt: user.premiumExpiresAt
        });
    } catch (e) {
        console.error(e);
        res.status(500).json({ success: false });
    }
});

// --- ADMIN API (OWNER ONLY) ---
// Middleware helper for owner
const ensureOwner = (req, res, next) => {
    // In a real app, use Sessions/JWT. Here we rely on the client knowing the flow, 
    // but we can pass the username in headers or body to basic check.
    // For this simplified version, we'll check the 'requesting-user' header.
    const user = req.headers['requesting-user'];
    if(user === 'Owner') next();
    else res.status(403).json({ success: false, message: "Forbidden" });
};

app.get('/api/admin/users', ensureOwner, async (req, res) => {
    try {
        // Fetch all users
        const users = await User.find({}, 'username knownIps isPremium premiumExpiresAt discordId');
        
        // Map to format for frontend
        const userList = users.map(u => ({
            id: u._id,
            username: u.username,
            ips: u.knownIps,
            isPremium: u.isPremium,
            premiumExpiresAt: u.premiumExpiresAt,
            discordId: u.discordId
        }));
        res.json(userList);
    } catch (e) { res.json([]); }
});

app.post('/api/admin/set-premium', ensureOwner, async (req, res) => {
    try {
        const { targetUserId, durationType, customValue } = req.body;
        const user = await User.findById(targetUserId);
        if(!user) return res.json({ success: false, message: "User not found" });

        if (durationType === "remove") {
            user.isPremium = false;
            user.premiumExpiresAt = null;
        } else {
            user.isPremium = true;
            if (durationType === "lifetime") {
                user.premiumExpiresAt = null;
            } else {
                const now = new Date();
                let addTime = 0;
                // Simple calculation based on rough ms
                const hour = 3600 * 1000;
                const day = 24 * hour;
                
                if (durationType === "hours") addTime = parseInt(customValue) * hour;
                else if (durationType === "days") addTime = parseInt(customValue) * day;
                else if (durationType === "weeks") addTime = parseInt(customValue) * 7 * day;
                else if (durationType === "months") addTime = parseInt(customValue) * 30 * day;
                
                user.premiumExpiresAt = new Date(now.getTime() + addTime);
            }
        }
        await user.save();
        res.json({ success: true });
    } catch(e) { res.json({ success: false }); }
});

app.post('/api/admin/ban-ip-list', ensureOwner, async (req, res) => {
    try {
        const { ips } = req.body;
        if (!ips || !Array.isArray(ips)) return res.json({ success: false });
        
        for (const ip of ips) {
             await BlacklistModel.findOneAndUpdate(
                { ip },
                { ip, expiresAt: null, reason: "Owner Ban" }, // Permanent ban
                { upsert: true, new: true }
            );
        }
        res.json({ success: true });
    } catch(e) { res.json({ success: false }); }
});

app.post('/api/admin/unban-ip-list', ensureOwner, async (req, res) => {
    try {
        const { ips } = req.body;
        if (!ips || !Array.isArray(ips)) return res.json({ success: false });
        await BlacklistModel.deleteMany({ ip: { $in: ips } });
        res.json({ success: true });
    } catch(e) { res.json({ success: false }); }
});


// --- APP MANAGEMENT ---
app.get('/api/my-apps', async (req, res) => {
    try {
        const { owner } = req.query;
        const myApps = await AppModel.find({ owner });
        res.json(myApps);
    } catch (e) { res.json([]); }
});

app.post('/api/create-app', async (req, res) => {
    try {
        const { name, owner } = req.body;
        const appId = generateId(10);
        const secret = generateId(40); 
        const newApp = new AppModel({ id: appId, name, owner, secret, totalUsers: 0, onlineUsers: 0 });
        await newApp.save();
        res.json({ success: true });
    } catch (e) { res.json({ success: false }); }
});

app.post('/api/delete-app', async (req, res) => {
    try {
        const { id, owner } = req.body;
        await AppModel.findOneAndDelete({ id: id, owner: owner });
        await KeyModel.deleteMany({ appId: id });
        res.json({ success: true });
    } catch (e) { res.json({ success: false }); }
});


// --- KEY MANAGEMENT ---
app.post('/api/create-key', async (req, res) => {
    try {
        const { owner, appId, durationType, customDays } = req.body;
        const application = await AppModel.findOne({ id: appId });
        if(!application) return res.json({ success: false });

        const keyStr = `VNT-${generateId(4).toUpperCase()}-${generateId(4).toUpperCase()}`;
        const expiresAt = calculateExpiry(durationType, customDays);
        let label = durationType === 'custom' ? `${customDays} Days` : durationType.toUpperCase();
        if(!expiresAt) label = "Lifetime";

        const newKey = new KeyModel({
            key: keyStr, 
            appId: appId, 
            appName: application.name, 
            generatedBy: owner,
            expiresAt: expiresAt,
            durationLabel: label,
            active: true
        });
        await newKey.save();
        res.json({ success: true, key: keyStr });
    } catch (e) { res.json({ success: false }); }
});

app.post('/api/delete-key', async (req, res) => {
    try {
        const { id, owner } = req.body;
        await KeyModel.findOneAndDelete({ _id: id });
        res.json({ success: true });
    } catch (e) { res.json({ success: false }); }
});

// --- DASHBOARD DATA ---
app.get('/api/dashboard-data', async (req, res) => {
    try {
        const { owner } = req.query;
        const apps = await AppModel.find({ owner });
        const myAppIds = apps.map(a => a.id);
        const myKeys = await KeyModel.find({ appId: { $in: myAppIds } }).sort({ createdAt: -1 });
        const myLogs = await LogModel.find({ owner: owner }).sort({ createdAt: -1 }).limit(100);
        res.json({ keys: myKeys, logs: myLogs });
    } catch (e) { res.json({ keys: [], logs: [] }); }
});


// --- BLACKLIST SYSTEM ---
app.post('/api/ban-ip', async (req, res) => {
    try {
        const { ip, durationDays } = req.body;
        if(!ip) return res.json({ success: false, message: "No IP" });
        const days = parseInt(durationDays);
        let expires = null;
        if(days > 0) {
            expires = new Date();
            expires.setDate(expires.getDate() + days);
        }
        await BlacklistModel.findOneAndUpdate(
            { ip },
            { ip, expiresAt: expires, reason: "Manual Ban" },
            { upsert: true, new: true }
        );
        res.json({ success: true });
    } catch(e) { res.json({ success: false }); }
});


// --- SCRIPT HOSTING ---
app.get('/api/my-scripts', async (req, res) => {
    try {
        const { owner } = req.query;
        const scripts = await ScriptModel.find({ owner });
        res.json(scripts);
    } catch (e) { res.json([]); }
});

app.post('/api/save-script', async (req, res) => {
    try {
        const { owner, label, content } = req.body;
        const count = await ScriptModel.countDocuments({ owner });
        
        // Check Premium for Limit
        const user = await User.findOne({ username: owner });
        const limit = (user && user.isPremium) ? 20 : 5; // Premium gets 20 scripts

        if (count >= limit) return res.json({ success: false, message: `Limit reached (Max ${limit})` });

        const filename = `s-${generateId(6)}.lua`;
        const newScript = new ScriptModel({ owner, filename, userLabel: label, content });
        await newScript.save();
        res.json({ success: true });
    } catch (e) { res.json({ success: false, message: "Error" }); }
});

app.post('/api/delete-script', async (req, res) => {
    try {
        const { id, owner } = req.body;
        await ScriptModel.findOneAndDelete({ _id: id, owner });
        res.json({ success: true });
    } catch (e) { res.json({ success: false }); }
});

app.get('/lua/:filename', async (req, res) => {
    try {
        const { filename } = req.params;
        const ip = getClientIp(req); 

        if (await isBlacklisted(ip)) return res.status(403).send("-- [[ BANNED IP ]] --");

        const script = await ScriptModel.findOne({ filename });
        if (!script) return res.status(404).send("Script not found");

        const userAgent = req.headers['user-agent'] || '';
        if (userAgent.includes('Mozilla') && !userAgent.includes('Roblox')) {
             return res.send(`-- [[ ACCESS DENIED ]] --\n-- Protected by VantaAuth.`);
        }

        await LogModel.create({
            time: getTime(),
            owner: script.owner,
            appId: "HOSTING",
            appName: `Script: ${script.userLabel}`,
            key: "N/A",
            ip: ip,
            message: "Script Executed/Downloaded",
            type: "execution"
        });

        res.setHeader('Content-Type', 'text/plain');
        res.send(script.content);

    } catch (e) { res.status(500).send("Error"); }
});


// --- LUA VERIFY ---
app.get('/api/lua/loader', (req, res) => {
    const lua = `
local Vanta = {}
local Http = game:GetService("HttpService")

function Vanta.Login(appId, secret, key)
    local url = "https://vantaauth1.onrender.com/api/lua/verify"
    local hwid = game:GetService("RbxAnalyticsService"):GetClientId()
    
    local body = Http:JSONEncode({ appId=appId, secret=secret, key=key, hwid=hwid })
    local resp = request({Url=url, Method="POST", Headers={["Content-Type"]="application/json"}, Body=body})
    
    if resp.StatusCode == 200 then
        local data = Http:JSONDecode(resp.Body)
        if data.valid then
            print("VantaAuth: Login OK!")
            loadstring(data.script)()
        else
            game.Players.LocalPlayer:Kick(data.message)
        end
    else
        warn("Server Error")
    end
end
return Vanta
    `;
    res.send(lua);
});

app.post('/api/lua/verify', async (req, res) => {
    const ip = getClientIp(req); 
    const { appId, secret, key, hwid } = req.body;

    try {
        if (await isBlacklisted(ip)) return res.json({ valid: false, message: "IP Banned" });

        const appData = await AppModel.findOne({ id: appId });
        if (!appData || appData.secret !== secret) return res.json({ valid: false, message: "Invalid App/Secret" });

        const logCommon = { time: getTime(), owner: appData.owner, appId, appName: appData.name, key, ip };

        const keyData = await KeyModel.findOne({ key: key });
        if (!keyData) return res.json({ valid: false, message: "Invalid Key" });
        if (keyData.appId !== appId) return res.json({ valid: false, message: "Key not for this App" });
        if (!keyData.active) return res.json({ valid: false, message: "Key Banned" });

        if (keyData.expiresAt && new Date() > new Date(keyData.expiresAt)) {
            return res.json({ valid: false, message: "Key Expired" });
        }

        if (!keyData.hwid) {
            keyData.hwid = hwid;
            keyData.ip = ip;
            await keyData.save();
            appData.totalUsers += 1;
            await appData.save();
        } else if (keyData.hwid !== hwid) {
            await LogModel.create({ ...logCommon, message: "HWID Mismatch Warning" });
            return res.json({ valid: false, message: "HWID Mismatch" });
        }

        await LogModel.create({ ...logCommon, message: "Login Success", type: "auth" });
        
        res.json({ valid: true, script: `print("Hello ${key} from ${appData.name}")` });

    } catch (e) {
        console.error(e);
        res.json({ valid: false, message: "Server Error" });
    }
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
