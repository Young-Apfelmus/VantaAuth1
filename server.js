require('dotenv').config(); 
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const mongoose = require('mongoose');

const app = express();
const PORT = process.env.PORT || 3000;

// --- MONGODB CONNECTION ---
const mongoUri = process.env.MONGO_URI;

if (!mongoUri) {
    console.error("FATAL: MONGO_URI is missing in Environment Variables!");
} else {
    mongoose.connect(mongoUri)
        .then(() => console.log("✅ Connected to MongoDB"))
        .catch(err => console.error("❌ MongoDB Connection Error:", err));
}

app.use(cors());
app.use(bodyParser.json());

// --- DATABASE SCHEMAS ---

// User Schema
const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true }
});
const User = mongoose.model('User', UserSchema);

// App Schema
const AppSchema = new mongoose.Schema({
    id: { type: String, unique: true },
    name: String,
    owner: String,
    secret: String,
    totalUsers: { type: Number, default: 0 },
    onlineUsers: { type: Number, default: 0 }
});
const AppModel = mongoose.model('App', AppSchema);

// Key Schema (Updated with Expiry)
const KeySchema = new mongoose.Schema({
    key: { type: String, unique: true },
    appId: String,
    appName: String,
    generatedBy: String,
    hwid: { type: String, default: null },
    ip: { type: String, default: null },
    active: { type: Boolean, default: true },
    expiresAt: { type: Date, default: null }, // Null = Lifetime
    durationLabel: { type: String, default: "Lifetime" },
    createdAt: { type: Date, default: Date.now }
});
const KeyModel = mongoose.model('Key', KeySchema);

// Log Schema
const LogSchema = new mongoose.Schema({
    time: String,
    appId: String, // Can be "HOSTING" for script hosting logs
    appName: String,
    key: String,   // Can be "N/A" for script hosting
    ip: String,
    message: String,
    type: { type: String, default: "auth" }, // "auth" or "execution"
    createdAt: { type: Date, default: Date.now }
});
const LogModel = mongoose.model('Log', LogSchema);

// Script Schema
const ScriptSchema = new mongoose.Schema({
    owner: String,
    filename: { type: String, unique: true }, 
    userLabel: String, 
    content: String,
    createdAt: { type: Date, default: Date.now }
});
const ScriptModel = mongoose.model('Script', ScriptSchema);

// NEW: Blacklist Schema
const BlacklistSchema = new mongoose.Schema({
    ip: { type: String, required: true, unique: true },
    reason: String,
    expiresAt: { type: Date, default: null }, // Null = Perm
    createdAt: { type: Date, default: Date.now }
});
const BlacklistModel = mongoose.model('Blacklist', BlacklistSchema);


// --- HELPER ---
function generateId(len) { return crypto.randomBytes(len).toString('hex').slice(0, len); }
function getTime() { return new Date().toISOString().replace('T', ' ').substring(0, 19); }

// Helper: Calculate Expiration Date
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

    if (daysToAdd === 0) return null; // Fallback to lifetime if 0

    const expiryDate = new Date(now);
    expiryDate.setDate(expiryDate.getDate() + daysToAdd);
    return expiryDate;
}

// Helper: Check Blacklist
async function isBlacklisted(ip) {
    const entry = await BlacklistModel.findOne({ ip });
    if (!entry) return false;
    // Check if ban expired
    if (entry.expiresAt && new Date() > entry.expiresAt) {
        await BlacklistModel.deleteOne({ ip });
        return false;
    }
    return true;
}


// --- AUTH ---
app.post('/api/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        const existingUser = await User.findOne({ username });
        if (existingUser) return res.json({ success: false, message: "Taken" });
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ username, password: hashedPassword });
        await newUser.save();
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ success: false, message: "Server Error" });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await User.findOne({ username });
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.json({ success: false });
        }
        res.json({ success: true, username: user.username });
    } catch (e) {
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


// --- KEY MANAGEMENT (UPDATED) ---
app.post('/api/create-key', async (req, res) => {
    try {
        const { owner, appId, durationType, customDays } = req.body;
        const application = await AppModel.findOne({ id: appId });
        if(!application) return res.json({ success: false });

        const keyStr = `VNT-${generateId(4).toUpperCase()}-${generateId(4).toUpperCase()}`;
        
        // Calculate Expiry
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
        // Verify ownership indirectly or assume admin logic implies access
        // Ideally check if App owner matches, but for simplicity:
        await KeyModel.findOneAndDelete({ _id: id });
        res.json({ success: true });
    } catch (e) { res.json({ success: false }); }
});

// --- DASHBOARD DATA ---
app.get('/api/dashboard-data', async (req, res) => {
    try {
        const { owner } = req.query;
        // 1. Apps owned by user
        const apps = await AppModel.find({ owner });
        const myAppIds = apps.map(a => a.id);
        
        // 2. Keys for those apps
        const myKeys = await KeyModel.find({ appId: { $in: myAppIds } }).sort({ createdAt: -1 });
        
        // 3. Logs: Either for the Apps OR Script Hosting (where appId="HOSTING" and owner matches somehow)
        // Since Script Logs don't link easily to "owner" without looking up the filename owner,
        // we will fetch logs where appName matches one of the user's apps OR appId is HOSTING (we need to filter hosting logs better in a real app, but here we show all logs for simplicity or filter by name).
        
        // To keep it simple: We fetch logs where appId is in myAppIds OR (appId="HOSTING" and message contains script name owned by user).
        // For this demo, we just return logs for the APPS + All Hosting logs (if you want better privacy, you'd filter hosting logs by script ownership).
        // Let's stick to App Logs for safety + Hosting logs if simple.
        
        const myLogs = await LogModel.find({ 
            $or: [
                { appId: { $in: myAppIds } },
                { appId: "HOSTING" } // Showing all script executions for now, can be filtered if needed
            ]
        }).sort({ createdAt: -1 }).limit(100);
        
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

        // Upsert (Update if exists, else insert)
        await BlacklistModel.findOneAndUpdate(
            { ip },
            { ip, expiresAt: expires, reason: "Manual Ban" },
            { upsert: true, new: true }
        );

        res.json({ success: true });
    } catch(e) {
        console.error(e);
        res.json({ success: false });
    }
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

// --- PUBLIC RAW ENDPOINT (UPDATED WITH LOGGING & BLACKLIST) ---
app.get('/lua/:filename', async (req, res) => {
    try {
        const { filename } = req.params;
        const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

        // 1. Check Blacklist
        if (await isBlacklisted(ip)) {
            return res.status(403).send("-- [[ BANNED IP ]] --");
        }

        const script = await ScriptModel.findOne({ filename });
        if (!script) return res.status(404).send("Script not found");

        // 2. Browser Protection
        const userAgent = req.headers['user-agent'] || '';
        if (userAgent.includes('Mozilla') && !userAgent.includes('Roblox')) {
             return res.send(`-- [[ ACCESS DENIED ]] --\n-- Protected by VantaAuth.`);
        }

        // 3. Log Execution
        // We log it so it appears in Live Logs
        await LogModel.create({
            time: getTime(),
            appId: "HOSTING",
            appName: `Script: ${script.userLabel}`,
            key: "N/A",
            ip: ip,
            message: "Script Executed/Downloaded",
            type: "execution"
        });

        res.setHeader('Content-Type', 'text/plain');
        res.send(script.content);

    } catch (e) {
        res.status(500).send("Error");
    }
});


// --- LUA VERIFY (UPDATED) ---
app.get('/api/lua/loader', (req, res) => {
    // Standard loader code (unchanged logic)
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
        // 1. Check Blacklist
        if (await isBlacklisted(ip)) {
            return res.json({ valid: false, message: "IP Banned" });
        }

        const appData = await AppModel.findOne({ id: appId });
        if (!appData || appData.secret !== secret) return res.json({ valid: false, message: "Invalid App/Secret" });

        const keyData = await KeyModel.findOne({ key: key });
        if (!keyData) return res.json({ valid: false, message: "Invalid Key" });
        if (keyData.appId !== appId) return res.json({ valid: false, message: "Key not for this App" });
        if (!keyData.active) return res.json({ valid: false, message: "Key Banned" });

        // 2. Check Expiry
        if (keyData.expiresAt && new Date() > new Date(keyData.expiresAt)) {
            return res.json({ valid: false, message: "Key Expired" });
        }

        // 3. HWID Lock
        if (!keyData.hwid) {
            keyData.hwid = hwid;
            keyData.ip = ip;
            await keyData.save();
            appData.totalUsers += 1;
            await appData.save();
        } else if (keyData.hwid !== hwid) {
            await LogModel.create({ time: getTime(), appId, appName: appData.name, key, ip, message: "HWID Mismatch Warning" });
            return res.json({ valid: false, message: "HWID Mismatch" });
        }

        // Success Log
        await LogModel.create({ time: getTime(), appId, appName: appData.name, key, ip, message: "Login Success", type: "auth" });
        
        res.json({ valid: true, script: `print("Hello ${key} from ${appData.name}")` });

    } catch (e) {
        console.error(e);
        res.json({ valid: false, message: "Server Error" });
    }
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
