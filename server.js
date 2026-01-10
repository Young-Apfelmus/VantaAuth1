require('dotenv').config(); 
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const mongoose = require('mongoose');
const axios = require('axios'); // REQUIREMENT: npm install axios

const app = express();
const PORT = process.env.PORT || 3000;

// --- CONFIGURATION ---
const MONGO_URI = process.env.MONGO_URI;
const DISCORD_CLIENT_ID = "1459637612246597916";
const DISCORD_CLIENT_SECRET = "y3EwGJXiKnlBM9i-Zh-4goite4-FtGjD";
const DISCORD_REDIRECT_URI = "https://vantaauth1.onrender.com/auth/discord/callback";
const FRONTEND_URL = "https://vantaauth.sharkservices075.workers.dev";

// --- DATABASE CONNECTION ---
if (!MONGO_URI) {
    console.error("FATAL: MONGO_URI is missing in Environment Variables!");
} else {
    mongoose.connect(MONGO_URI)
        .then(() => console.log("✅ Connected to MongoDB"))
        .catch(err => console.error("❌ MongoDB Connection Error:", err));
}

app.use(cors());
app.use(bodyParser.json());

// --- DATABASE SCHEMAS ---

const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    discordId: { type: String, required: true }, // NEW: Link to Discord
    knownIps: { type: [String], default: [] }    // NEW: IP Whitelist
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

// --- DISCORD OAUTH2 HANDLER ---
// 1. Get the Login URL
app.get('/auth/discord/url', (req, res) => {
    const url = `https://discord.com/api/oauth2/authorize?client_id=${DISCORD_CLIENT_ID}&redirect_uri=${encodeURIComponent(DISCORD_REDIRECT_URI)}&response_type=code&scope=identify`;
    res.json({ url });
});

// 2. Callback from Discord
app.get('/auth/discord/callback', async (req, res) => {
    const { code } = req.query;
    if (!code) return res.send("No code provided.");

    try {
        // Exchange code for token
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

        // Get User Info
        const userResponse = await axios.get('https://discord.com/api/users/@me', {
            headers: { Authorization: `Bearer ${accessToken}` }
        });

        const discordUser = userResponse.data;
        
        // Encode data to pass back to frontend (Simple base64 for transport)
        const payload = Buffer.from(JSON.stringify({
            id: discordUser.id,
            username: discordUser.username
        })).toString('base64');

        // Redirect back to frontend with the payload
        res.redirect(`${FRONTEND_URL}?discord_auth=${payload}`);

    } catch (e) {
        console.error("Discord Auth Error:", e.response ? e.response.data : e.message);
        res.send("Authentication Failed. Please try again.");
    }
});


// --- AUTHENTICATION (UPDATED) ---

// REGISTER: Now requires discordData (passed from frontend after OAuth)
app.post('/api/register', async (req, res) => {
    try {
        const { username, password, discordId } = req.body;
        const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

        if (!discordId) return res.json({ success: false, message: "Discord Verification Missing" });

        const existingUser = await User.findOne({ username });
        if (existingUser) return res.json({ success: false, message: "Username Taken" });
        
        // Check if Discord ID is already used
        const existingDiscord = await User.findOne({ discordId });
        if (existingDiscord) return res.json({ success: false, message: "Discord Account already linked to a user" });

        const hashedPassword = await bcrypt.hash(password, 10);
        
        const newUser = new User({ 
            username, 
            password: hashedPassword,
            discordId: discordId,
            knownIps: [ip] // Save initial IP
        });
        
        await newUser.save();
        res.json({ success: true });
    } catch (e) {
        console.error(e);
        res.status(500).json({ success: false, message: "Server Error" });
    }
});

// LOGIN: Checks IP and demands verification if new
app.post('/api/login', async (req, res) => {
    try {
        const { username, password, verificationDiscordId } = req.body;
        const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

        const user = await User.findOne({ username });
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.json({ success: false, message: "Invalid Credentials" });
        }

        // IP CHECK LOGIC
        const isKnownIp = user.knownIps.includes(ip);

        if (!isKnownIp) {
            // If user provided a verification ID from the OAuth flow
            if (verificationDiscordId) {
                if (verificationDiscordId === user.discordId) {
                    // VERIFIED: Add new IP to whitelist and allow login
                    user.knownIps.push(ip);
                    await user.save();
                } else {
                    return res.json({ success: false, message: "Wrong Discord Account! Use the one linked to this user." });
                }
            } else {
                // Not verified yet, tell frontend to trigger Discord OAuth
                return res.json({ success: false, requireVerification: true, message: "New IP detected. Please verify with Discord." });
            }
        }

        res.json({ success: true, username: user.username });
    } catch (e) {
        console.error(e);
        res.status(500).json({ success: false });
    }
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
        if (count >= 5) return res.json({ success: false, message: "Limit reached (Max 5)" });

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
        const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

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
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
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
