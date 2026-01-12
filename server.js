require('dotenv').config(); 
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const mongoose = require('mongoose');
const axios = require('axios'); 
const path = require('path');
const { Client, GatewayIntentBits, Partials, EmbedBuilder, ActionRowBuilder, ButtonBuilder, ButtonStyle, ModalBuilder, TextInputBuilder, TextInputStyle, REST, Routes, ActivityType } = require('discord.js');

const app = express();
const PORT = process.env.PORT || 3000;

// --- CONFIGURATION ---
const MONGO_URI = process.env.MONGO_URI;
const DISCORD_CLIENT_ID = "1459637612246597916";
const DISCORD_CLIENT_SECRET = "y3EwGJXiKnlBM9i-Zh-4goite4-FtGjD";
const DISCORD_REDIRECT_URI = "https://vanta-api.xyz/auth/discord/callback";
const FRONTEND_URL = "https://vantaauth.xyz";

// --- DATABASE CONNECTION ---
if (!MONGO_URI) {
    console.error("FATAL: MONGO_URI is missing in Environment Variables!");
} else {
    mongoose.connect(MONGO_URI)
        .then(() => {
            console.log("✅ Connected to MongoDB");
            createOwnerAccount(); 
            restoreBots(); // Start bots on server restart
        })
        .catch(err => console.error("❌ MongoDB Connection Error:", err));
}

app.use(cors());
app.use(bodyParser.json());
app.use(express.static(__dirname));

// --- HELPER: GET CLEAN IP ---
function getClientIp(req) {
    const forwarded = req.headers['x-forwarded-for'];
    if (forwarded) {
        return forwarded.split(',')[0].trim();
    }
    return req.socket.remoteAddress;
}

// --- HELPER: GET ID FROM TOKEN ---
function getClientIdFromToken(token) {
    try {
        const parts = token.split('.');
        if (parts.length < 2) return null;
        const decoded = Buffer.from(parts[0], 'base64').toString('utf-8');
        return decoded;
    } catch (e) {
        return null;
    }
}

// --- DATABASE SCHEMAS ---

const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    discordId: { type: String, required: false }, 
    discordAvatar: { type: String, default: null }, 
    knownIps: { type: [String], default: [] },
	isOwner: { type: Boolean, default: false }, 
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

// --- NEW SCHEMAS FOR LUA COMFORT ---

const BotSchema = new mongoose.Schema({
    owner: String,
    token: { type: String, required: true },
    clientId: String,
    botUsername: String,
    botAvatar: String, // Stores the avatar URL
    isConnected: { type: Boolean, default: false },
    config: {
        embedTitle: { type: String, default: "Vantarmor x VantaAuth" },
        embedDesc: { type: String, default: "Manage your subscription below." },
        embedImage: { type: String, default: "https://media.discordapp.net/attachments/1441485788583038989/1459280667522109460/Airbrush-OBJECT-REMOVER-1767990007080.jpg" },
        premiumRoleId: { type: String, default: "" },
        // Linked App for security
        linkedAppId: { type: String, default: "" },
        linkedAppSecret: { type: String, default: "" },
        // This now stores the URL, not the content
        scriptLoadstring: { type: String, default: "" } 
    },
    createdAt: { type: Date, default: Date.now }
});
const BotModel = mongoose.model('Bot', BotSchema);

const RedemptionSchema = new mongoose.Schema({
    discordUserId: String,
    botClientId: String,
    redeemedKey: String,
    isWhitelisted: { type: Boolean, default: false },
    redeemedAt: { type: Date, default: Date.now }
});
const RedemptionModel = mongoose.model('Redemption', RedemptionSchema);


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
        let owner = await User.findOne({ username: "Owner" });
        if (!owner) {
            const hashedPassword = await bcrypt.hash("Owner", 10);
            await User.create({ username: "Owner", password: hashedPassword, discordId: "OWNER-SYSTEM", isPremium: true, isOwner: true });
            console.log("👑 Owner Account Created");
        } else {
            if (!owner.isOwner) { owner.isOwner = true; owner.isPremium = true; await owner.save(); }
        }
    } catch (e) { console.error("Owner Seed Error", e); }
}

// --- DISCORD OAUTH2 HANDLER (VANTA LOGIN) ---
app.get('/auth/discord/url', (req, res) => {
    const url = `https://discord.com/api/oauth2/authorize?client_id=${DISCORD_CLIENT_ID}&redirect_uri=${encodeURIComponent(DISCORD_REDIRECT_URI)}&response_type=code&scope=identify`;
    res.json({ url });
});

app.get('/auth/discord/callback', async (req, res) => {
    const { code } = req.query;
    if (!code) return res.send("No code provided.");
    try {
        const tokenResponse = await axios.post('https://discord.com/api/oauth2/token', new URLSearchParams({
                client_id: DISCORD_CLIENT_ID, client_secret: DISCORD_CLIENT_SECRET, grant_type: 'authorization_code', code, redirect_uri: DISCORD_REDIRECT_URI
            }), { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } });
        const accessToken = tokenResponse.data.access_token;
        const userResponse = await axios.get('https://discord.com/api/users/@me', { headers: { Authorization: `Bearer ${accessToken}` } });
        const discordUser = userResponse.data;
        const payload = Buffer.from(JSON.stringify({ id: discordUser.id, username: discordUser.username, avatar: discordUser.avatar })).toString('base64');
        res.redirect(`${FRONTEND_URL}?discord_auth=${payload}`);
    } catch (e) { res.send("Authentication Failed."); }
});


// --- AUTHENTICATION ---
app.post('/api/register', async (req, res) => {
    try {
        const { username, password, discordId, discordAvatar } = req.body;
        const ip = getClientIp(req); 
        if (await isBlacklisted(ip)) return res.json({ success: false, message: "Your IP is banned." });
        if (!discordId) return res.json({ success: false, message: "Discord Verification Missing" });
        const existingUser = await User.findOne({ username });
        if (existingUser) return res.json({ success: false, message: "Username Taken" });
        const existingDiscord = await User.findOne({ discordId });
        if (existingDiscord) return res.json({ success: false, message: "Discord Account already linked" });
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ username, password: hashedPassword, discordId, discordAvatar, knownIps: [ip] });
        await newUser.save();
        res.json({ success: true, username, isPremium: false, premiumExpiresAt: null, discordId, discordAvatar });
    } catch (e) { res.status(500).json({ success: false, message: "Server Error" }); }
});

app.post('/api/login', async (req, res) => {
    try {
        const { username, password, verificationDiscordId, verificationAvatar } = req.body;
        const ip = getClientIp(req); 
        if (await isBlacklisted(ip)) return res.json({ success: false, message: "Your IP is banned." });
        const user = await User.findOne({ username });
        if (!user || !(await bcrypt.compare(password, user.password))) return res.json({ success: false, message: "Invalid Credentials" });

        if (user.username === "Owner") {
             if(!user.knownIps.includes(ip)) { user.knownIps.push(ip); await user.save(); }
             return res.json({ success: true, username: user.username, isOwner: true, isPremium: true, premiumExpiresAt: null, discordId: user.discordId, discordAvatar: user.discordAvatar });
        }

        const isKnownIp = user.knownIps.includes(ip);
        if (!isKnownIp) {
            if (verificationDiscordId) {
                if (verificationDiscordId === user.discordId) {
                    user.knownIps.push(ip);
                    if(verificationAvatar) user.discordAvatar = verificationAvatar;
                    await user.save();
                } else return res.json({ success: false, message: "Wrong Discord Account!" });
            } else return res.json({ success: false, requireVerification: true, message: "New IP. Verify with Discord." });
        }

        if (user.isPremium && user.premiumExpiresAt) {
            if (new Date() > new Date(user.premiumExpiresAt)) { user.isPremium = false; user.premiumExpiresAt = null; await user.save(); }
        }
        res.json({ success: true, username: user.username, isOwner: user.isOwner, isPremium: user.isPremium, premiumExpiresAt: user.premiumExpiresAt, discordId: user.discordId, discordAvatar: user.discordAvatar });
    } catch (e) { res.status(500).json({ success: false }); }
});

// --- ADMIN API ---
const ensureOwner = async (req, res, next) => {
    const username = req.headers['requesting-user'];
    if(!username) return res.status(403).json({ success: false });
    const user = await User.findOne({ username });
    if(user && user.isOwner) next();
    else res.status(403).json({ success: false });
};

app.get('/api/admin/users', ensureOwner, async (req, res) => {
    try {
        const users = await User.find({}, 'username knownIps isPremium premiumExpiresAt discordId isOwner');
        res.json(users.map(u => ({ id: u._id, username: u.username, ips: u.knownIps, isPremium: u.isPremium, isOwner: u.isOwner, premiumExpiresAt: u.premiumExpiresAt, discordId: u.discordId })));
    } catch (e) { res.json([]); }
});

app.post('/api/admin/set-premium', ensureOwner, async (req, res) => {
    try {
        const { targetUserId, durationType, customValue } = req.body;
        const user = await User.findById(targetUserId);
        if(!user) return res.json({ success: false });
        if (durationType === "remove") { user.isPremium = false; user.premiumExpiresAt = null; }
        else {
            user.isPremium = true;
            if (durationType === "lifetime") user.premiumExpiresAt = null;
            else {
                const now = new Date();
                let addTime = 0; const hour = 3600 * 1000;
                if (durationType === "hours") addTime = parseInt(customValue) * hour;
                else if (durationType === "days") addTime = parseInt(customValue) * 24 * hour;
                else if (durationType === "weeks") addTime = parseInt(customValue) * 7 * 24 * hour;
                else if (durationType === "months") addTime = parseInt(customValue) * 30 * 24 * hour;
                user.premiumExpiresAt = new Date(now.getTime() + addTime);
            }
        }
        await user.save(); res.json({ success: true });
    } catch(e) { res.json({ success: false }); }
});

app.post('/api/admin/ban-ip-list', ensureOwner, async (req, res) => {
    try {
        const { ips } = req.body;
        for (const ip of ips) { await BlacklistModel.findOneAndUpdate({ ip }, { ip, expiresAt: null, reason: "Owner Ban" }, { upsert: true, new: true }); }
        res.json({ success: true });
    } catch(e) { res.json({ success: false }); }
});
app.post('/api/admin/unban-ip-list', ensureOwner, async (req, res) => {
    try { await BlacklistModel.deleteMany({ ip: { $in: req.body.ips } }); res.json({ success: true }); } catch(e) { res.json({ success: false }); }
});
app.post('/api/admin/toggle-owner', ensureOwner, async (req, res) => {
    try {
        const { targetUserId, makeOwner } = req.body;
        const user = await User.findById(targetUserId);
        if(user.username === "Owner") return res.json({ success: false });
        user.isOwner = makeOwner; if(makeOwner) user.isPremium = true; 
        await user.save(); res.json({ success: true });
    } catch(e) { res.json({ success: false }); }
});

// --- APP & KEY MANAGEMENT ---
app.get('/api/my-apps', async (req, res) => {
    try { const myApps = await AppModel.find({ owner: req.query.owner }); res.json(myApps); } catch (e) { res.json([]); }
});
app.post('/api/create-app', async (req, res) => {
    try {
        const { name, owner } = req.body;
        const newApp = new AppModel({ id: generateId(10), name, owner, secret: generateId(40) });
        await newApp.save(); res.json({ success: true });
    } catch (e) { res.json({ success: false }); }
});
app.post('/api/delete-app', async (req, res) => {
    try {
        await AppModel.findOneAndDelete({ id: req.body.id, owner: req.body.owner });
        await KeyModel.deleteMany({ appId: req.body.id });
        res.json({ success: true });
    } catch (e) { res.json({ success: false }); }
});

app.post('/api/create-key', async (req, res) => {
    try {
        const { owner, appId, durationType, customDays } = req.body;
        const user = await User.findOne({ username: owner });
        const limit = user.isPremium ? 100 : 30;
        const currentKeys = await KeyModel.countDocuments({ generatedBy: owner });
        if (currentKeys >= limit) return res.json({ success: false, message: "Limit Reached" });

        const appData = await AppModel.findOne({ id: appId });
        const keyStr = `VNT-${generateId(4).toUpperCase()}-${generateId(4).toUpperCase()}`;
        const expiresAt = calculateExpiry(durationType, customDays);
        await KeyModel.create({ key: keyStr, appId, appName: appData.name, generatedBy: owner, expiresAt, durationLabel: expiresAt ? durationType : "Lifetime" });
        res.json({ success: true });
    } catch (e) { res.json({ success: false }); }
});

app.post('/api/delete-key', async (req, res) => {
    try { await KeyModel.findOneAndDelete({ _id: req.body.id }); res.json({ success: true }); } catch (e) { res.json({ success: false }); }
});

app.get('/api/dashboard-data', async (req, res) => {
    try {
        const { owner } = req.query;
        const user = await User.findOne({ username: owner });
        const apps = await AppModel.find({ owner });
        const keys = await KeyModel.find({ appId: { $in: apps.map(a => a.id) } }).sort({ createdAt: -1 });
        let logs = [];
        if (user && user.isPremium) logs = await LogModel.find({ owner }).sort({ createdAt: -1 }).limit(100);
        res.json({ keys, logs });
    } catch (e) { res.json({ keys: [], logs: [] }); }
});

// --- BLACKLIST & SCRIPTS ---
app.post('/api/ban-ip', async (req, res) => {
    try {
        const { ip, durationDays } = req.body;
        const days = parseInt(durationDays);
        let expires = days > 0 ? new Date(new Date().setDate(new Date().getDate() + days)) : null;
        await BlacklistModel.findOneAndUpdate({ ip }, { ip, expiresAt: expires, reason: "Manual Ban" }, { upsert: true, new: true });
        res.json({ success: true });
    } catch(e) { res.json({ success: false }); }
});
app.post('/api/unban-ip', async (req, res) => {
    try { await BlacklistModel.findOneAndDelete({ ip: req.body.ip }); res.json({ success: true }); } catch(e) { res.json({ success: false }); }
});

app.get('/api/my-scripts', async (req, res) => {
    try { res.json(await ScriptModel.find({ owner: req.query.owner })); } catch (e) { res.json([]); }
});
app.post('/api/save-script', async (req, res) => {
    try {
        const { owner, label, content } = req.body;
        const user = await User.findOne({ username: owner });
        const limit = (user && user.isPremium) ? 20 : 5;
        if (await ScriptModel.countDocuments({ owner }) >= limit) return res.json({ success: false, message: "Limit Reached" });
        await ScriptModel.create({ owner, filename: `s-${generateId(6)}.lua`, userLabel: label, content });
        res.json({ success: true });
    } catch (e) { res.json({ success: false }); }
});
app.post('/api/delete-script', async (req, res) => {
    try { await ScriptModel.findOneAndDelete({ _id: req.body.id, owner: req.body.owner }); res.json({ success: true }); } catch (e) { res.json({ success: false }); }
});
app.get('/lua/:filename', async (req, res) => {
    try {
        const ip = getClientIp(req);
        if (await isBlacklisted(ip)) return res.status(403).send("-- [[ BANNED IP ]] --");
        const script = await ScriptModel.findOne({ filename: req.params.filename });
        if (!script) return res.status(404).send("Script not found");
        await LogModel.create({ time: getTime(), owner: script.owner, appId: "HOSTING", appName: `Script: ${script.userLabel}`, key: "N/A", ip, message: "Script Downloaded", type: "execution" });
        res.setHeader('Content-Type', 'text/plain'); res.send(script.content);
    } catch (e) { res.status(500).send("Error"); }
});

// --- LUA VERIFY ---
app.get('/api/lua/loader', (req, res) => {
    res.send(`local Vanta = {}; local Http = game:GetService("HttpService"); function Vanta.Login(appId, secret, key) local url = "https://vanta-api.xyz/api/lua/verify"; local hwid = game:GetService("RbxAnalyticsService"):GetClientId(); local body = Http:JSONEncode({ appId=appId, secret=secret, key=key, hwid=hwid }); local resp = request({Url=url, Method="POST", Headers={["Content-Type"]="application/json"}, Body=body}); if resp.StatusCode == 200 then local data = Http:JSONDecode(resp.Body); if data.valid then loadstring(data.script)(); return true; else game.Players.LocalPlayer:Kick(data.message); return false; end else warn("Server Error"); return false; end end return Vanta`);
});

app.post('/api/lua/verify', async (req, res) => {
    const ip = getClientIp(req);
    const { appId, secret, key, hwid } = req.body;
    try {
        if (await isBlacklisted(ip)) return res.json({ valid: false, message: "IP Banned" });
        const appData = await AppModel.findOne({ id: appId });
        if (!appData || appData.secret !== secret) return res.json({ valid: false, message: "Invalid App" });
        const keyData = await KeyModel.findOne({ key });
        if (!keyData || !keyData.active) return res.json({ valid: false, message: "Invalid/Banned Key" });
        if (keyData.appId !== appId) return res.json({ valid: false, message: "Wrong App" });
        if (keyData.expiresAt && new Date() > new Date(keyData.expiresAt)) return res.json({ valid: false, message: "Key Expired" });
        
        if (!keyData.hwid) { keyData.hwid = hwid; keyData.ip = ip; await keyData.save(); appData.totalUsers += 1; await appData.save(); }
        else if (keyData.hwid !== hwid) {
            await LogModel.create({ time: getTime(), owner: appData.owner, appId, appName: appData.name, key, ip, message: "HWID Mismatch", type: "auth" });
            return res.json({ valid: false, message: "HWID Locked" });
        }
        await LogModel.create({ time: getTime(), owner: appData.owner, appId, appName: appData.name, key, ip, message: "Login Success", type: "auth" });
        res.json({ valid: true, script: `print("Logged in")`, expiryDate: keyData.expiresAt || "Lifetime" });
    } catch (e) { res.json({ valid: false, message: "Error" }); }
});

// ==========================================================
// --- LUA COMFORT (DISCORD BOT INTEGRATION) ---
// ==========================================================

// Global Map to hold active bot clients: Map<BotDB_ID, DiscordClient>
const activeBots = new Map();

// --- 1. BOT MANAGER FUNCTIONS ---

async function updateBotProfile(client, token) {
    try {
        const TARGET_NAME = "Vanta Auth - Lua";
        const TARGET_PFP = "https://media.discordapp.net/attachments/1441485788583038989/1459280667522109460/Airbrush-OBJECT-REMOVER-1767990007080.jpg?ex=69655787&is=69640607&hm=f13bcac738cd8b277c82f574a84e190ebfa9317e85949d7265667e8dc0f94bd3&=&format=webp&width=968&height=968";
        
        if(client.user.username !== TARGET_NAME) {
            await client.user.setUsername(TARGET_NAME);
        }
        try { 
            await client.user.setAvatar(TARGET_PFP); 
        } catch(e) {
            console.warn("Avatar update rate limited or identical.");
        }
        client.user.setActivity("Official Vanta AuthARMOR Bot", { type: ActivityType.Custom });
        return true;
    } catch(e) {
        console.error("Profile Update Error:", e.message);
        return false;
    }
}

async function startBot(botDoc) {
    if (activeBots.has(botDoc._id.toString())) return activeBots.get(botDoc._id.toString());

    const client = new Client({ intents: [GatewayIntentBits.Guilds] });

    client.on('error', (err) => console.error(`Bot Error (${botDoc.botUsername}):`, err));

    client.once('ready', async () => {
        console.log(`🤖 Bot Started: ${client.user.tag} (ID: ${client.user.id})`);
        
        try { await updateBotProfile(client, botDoc.token); } catch (e) {}
        
        const commands = [
            { name: 'setup', description: 'Configure Vanta App & Embed (Admin)' },
            { name: 'embed', description: 'Post Authentication Panel' },
        ];

        const rest = new REST({ version: '10' }).setToken(botDoc.token);
        try {
            await rest.put(Routes.applicationCommands(client.user.id), { body: commands });
        } catch (error) { console.error("Command Register Error:", error); }

        botDoc.isConnected = true;
        botDoc.clientId = client.user.id; 
        botDoc.botUsername = client.user.username;
        botDoc.botAvatar = client.user.avatarURL(); // Update DB with current avatar
        await botDoc.save();
    });

    client.on('interactionCreate', async interaction => {
        try {
            const currentBot = await BotModel.findById(botDoc._id);
            if (!currentBot) return interaction.reply({ content: "❌ Error: Bot removed from database.", ephemeral: true });

            // --- COMMANDS ---
            if (interaction.isCommand()) {
                if (interaction.commandName === 'setup') {
                    if (!interaction.member.permissions.has("Administrator")) {
                        return interaction.reply({ content: "You need Administrator permissions.", ephemeral: true });
                    }

                    const modal = new ModalBuilder().setCustomId('vanta_setup_modal').setTitle('Vanta Auth Setup');

                    // MODIFIED: Now asks for App ID and Secret
                    const appIdInput = new TextInputBuilder().setCustomId('setup_appid').setLabel("Vanta App ID").setValue(currentBot.config.linkedAppId || "").setStyle(TextInputStyle.Short);
                    const secretInput = new TextInputBuilder().setCustomId('setup_secret').setLabel("Vanta App Secret").setValue(currentBot.config.linkedAppSecret || "").setStyle(TextInputStyle.Short);
                    const titleInput = new TextInputBuilder().setCustomId('setup_title').setLabel("Embed Title").setValue(currentBot.config.embedTitle).setStyle(TextInputStyle.Short);
                    const descInput = new TextInputBuilder().setCustomId('setup_desc').setLabel("Embed Description").setValue(currentBot.config.embedDesc).setStyle(TextInputStyle.Paragraph);
                    const roleInput = new TextInputBuilder().setCustomId('setup_role').setLabel("Premium Role ID (Optional)").setValue(currentBot.config.premiumRoleId || "").setRequired(false).setStyle(TextInputStyle.Short);

                    modal.addComponents(
                        new ActionRowBuilder().addComponents(appIdInput),
                        new ActionRowBuilder().addComponents(secretInput),
                        new ActionRowBuilder().addComponents(titleInput),
                        new ActionRowBuilder().addComponents(descInput),
                        new ActionRowBuilder().addComponents(roleInput)
                    );

                    await interaction.showModal(modal);
                }

                if (interaction.commandName === 'embed') {
                     if (!currentBot.config.linkedAppId || !currentBot.config.linkedAppSecret) {
                         return interaction.reply({ content: "⚠️ Please run /setup first to link your Vanta Application!", ephemeral: true });
                     }
                     if (!currentBot.config.scriptLoadstring) {
                         return interaction.reply({ content: "⚠️ Please configure the Script Loadstring in the Web Dashboard first!", ephemeral: true });
                     }

                     const embed = new EmbedBuilder()
                        .setTitle(currentBot.config.embedTitle)
                        .setDescription(currentBot.config.embedDesc)
                        .setImage(currentBot.config.embedImage)
                        .setColor(0x00ff00)
                        .setFooter({ text: `Vanta Auth - App: ${currentBot.config.linkedAppId}` });

                     const row = new ActionRowBuilder().addComponents(
                         new ButtonBuilder().setCustomId('btn_redeem').setLabel('Redeem Key').setStyle(ButtonStyle.Success).setEmoji('🔑'),
                         new ButtonBuilder().setCustomId('btn_script').setLabel('Get Script').setStyle(ButtonStyle.Primary).setEmoji('📜'),
                         new ButtonBuilder().setCustomId('btn_role').setLabel('Get Role').setStyle(ButtonStyle.Primary).setEmoji('👤'),
                         new ButtonBuilder().setCustomId('btn_hwid').setLabel('Reset HWID').setStyle(ButtonStyle.Secondary).setEmoji('⚙️')
                     );

                     await interaction.reply({ embeds: [embed], components: [row] });
                }
            }

            // --- MODALS ---
            if (interaction.isModalSubmit()) {
                if (interaction.customId === 'vanta_setup_modal') {
                    const appId = interaction.fields.getTextInputValue('setup_appid');
                    const secret = interaction.fields.getTextInputValue('setup_secret');
                    const title = interaction.fields.getTextInputValue('setup_title');
                    const desc = interaction.fields.getTextInputValue('setup_desc');
                    const role = interaction.fields.getTextInputValue('setup_role');

                    currentBot.config.linkedAppId = appId;
                    currentBot.config.linkedAppSecret = secret;
                    currentBot.config.embedTitle = title;
                    currentBot.config.embedDesc = desc;
                    currentBot.config.premiumRoleId = role;
                    await currentBot.save(); 

                    await interaction.reply({ content: "✅ Setup Saved! Keys are now linked to App ID: " + appId, ephemeral: true });
                }
                
                if (interaction.customId === 'redeem_modal') {
                    const keyInput = interaction.fields.getTextInputValue('key_input');
                    
                    // Validate Key against Linked App
                    const keyData = await KeyModel.findOne({ key: keyInput });
                    
                    if (!keyData) return interaction.reply({ content: "❌ Invalid Key.", ephemeral: true });
                    if (!keyData.active) return interaction.reply({ content: "❌ Key is Banned.", ephemeral: true });
                    
                    // STRICT CHECK: Must match configured App ID
                    if (currentBot.config.linkedAppId && keyData.appId !== currentBot.config.linkedAppId) {
                        return interaction.reply({ content: `❌ This key is not for App ID: ${currentBot.config.linkedAppId}`, ephemeral: true });
                    }
                    
                    if (keyData.expiresAt && new Date() > new Date(keyData.expiresAt)) {
                        return interaction.reply({ content: "❌ Key Expired.", ephemeral: true });
                    }

                    await RedemptionModel.findOneAndUpdate(
                        { discordUserId: interaction.user.id, botClientId: client.user.id },
                        { redeemedKey: keyInput, isWhitelisted: true, redeemedAt: new Date() },
                        { upsert: true }
                    );

                    await interaction.reply({ content: "✅ Key Redeemed! You are now whitelisted.", ephemeral: true });
                }
            }

            // --- BUTTONS ---
            if (interaction.isButton()) {
                if (interaction.customId === 'btn_redeem') {
                    const modal = new ModalBuilder().setCustomId('redeem_modal').setTitle('Redeem License');
                    const keyInput = new TextInputBuilder().setCustomId('key_input').setLabel("License Key").setStyle(TextInputStyle.Short);
                    modal.addComponents(new ActionRowBuilder().addComponents(keyInput));
                    await interaction.showModal(modal);
                }
                
                else if (interaction.customId === 'btn_script') {
                    const redemption = await RedemptionModel.findOne({ discordUserId: interaction.user.id, botClientId: client.user.id });
                    if (!redemption || !redemption.isWhitelisted) return interaction.reply({ content: "❌ You must redeem a key first!", ephemeral: true });

                    const key = redemption.redeemedKey;
                    
                    // Double check Validity (Expiry/Ban) on click
                    const keyCheck = await KeyModel.findOne({ key });
                    if(!keyCheck || !keyCheck.active || (keyCheck.expiresAt && new Date() > new Date(keyCheck.expiresAt))) {
                         return interaction.reply({ content: "❌ Your key is banned or expired.", ephemeral: true });
                    }

                    // GENERATE PROTECTED LOADSTRING
                    // We point to our internal API which validates header/key before serving the real URL
                    const protectedUrl = `https://vanta-api.xyz/api/lua/protected-script?botId=${currentBot._id}&key=${key}`;

                    const finalCode = `
getgenv().VantaKey = "${key}"
loadstring(game:HttpGet("${protectedUrl}"))()
`;
                    await interaction.reply({ content: `Here is your script loader:\n\`\`\`lua\n${finalCode}\n\`\`\``, ephemeral: true });
                }

                else if (interaction.customId === 'btn_role') {
                    const redemption = await RedemptionModel.findOne({ discordUserId: interaction.user.id, botClientId: client.user.id });
                    if (!redemption || !redemption.isWhitelisted) return interaction.reply({ content: "❌ Redeem key first!", ephemeral: true });
                    
                    const roleId = currentBot.config.premiumRoleId;
                    if(!roleId) return interaction.reply({ content: "❌ No Role configured by admin.", ephemeral: true });

                    const role = interaction.guild.roles.cache.get(roleId);
                    if(role) {
                        try {
                            await interaction.member.roles.add(role);
                            await interaction.reply({ content: "✅ Role Added!", ephemeral: true });
                        } catch(e) {
                            await interaction.reply({ content: "❌ Bot missing permissions to give role.", ephemeral: true });
                        }
                    } else {
                        await interaction.reply({ content: "❌ Role not found.", ephemeral: true });
                    }
                }

                else if (interaction.customId === 'btn_hwid') {
                    const redemption = await RedemptionModel.findOne({ discordUserId: interaction.user.id, botClientId: client.user.id });
                    if (!redemption) return interaction.reply({ content: "❌ Redeem key first!", ephemeral: true });

                    const keyData = await KeyModel.findOne({ key: redemption.redeemedKey });
                    if(keyData) {
                        keyData.hwid = null;
                        await keyData.save();
                        await interaction.reply({ content: "✅ HWID Reset Successful!", ephemeral: true });
                    } else {
                        await interaction.reply({ content: "❌ Key invalid.", ephemeral: true });
                    }
                }
            }

        } catch (err) { console.error("Interaction Error", err); }
    });

    try {
        await client.login(botDoc.token);
        activeBots.set(botDoc._id.toString(), client);
        return client;
    } catch (e) {
        console.error("Login Failed for bot:", botDoc._id);
        botDoc.isConnected = false;
        await botDoc.save();
        return null;
    }
}

async function restoreBots() {
    console.log("🔄 Restoring Bots...");
    const bots = await BotModel.find({});
    for(const bot of bots) {
        await startBot(bot);
    }
}

// --- 2. API ENDPOINTS ---

// List Bots (Fixes Status & Avatar)
app.get('/api/bots', async (req, res) => {
    try {
        const { owner } = req.query;
        const user = await User.findOne({ username: owner });
        if(!user || !user.isPremium) return res.status(403).json({ error: "Premium Required" });

        const bots = await BotModel.find({ owner });
        
        const data = bots.map(b => {
            const client = activeBots.get(b._id.toString());
            const isOnline = client && client.ws.ping !== -1;
            
            // Priority: Live Avatar -> DB Avatar -> Default
            let avatarUrl = "https://cdn.discordapp.com/embed/avatars/0.png";
            if (client && client.user.avatarURL()) avatarUrl = client.user.avatarURL();
            else if (b.botAvatar) avatarUrl = b.botAvatar;

            return {
                id: b._id,
                name: b.botUsername || "Unknown",
                avatar: avatarUrl,
                isConnected: isOnline,
                ping: isOnline ? client.ws.ping : 0,
                clientId: b.clientId
            };
        });
        res.json(data);
    } catch(e) { res.json([]); }
});

app.post('/api/bots/connect', async (req, res) => {
    try {
        const { owner, token } = req.body;
        const user = await User.findOne({ username: owner });
        
        if(!user.isPremium) return res.json({ success: false, message: "Premium only feature." });
        const count = await BotModel.countDocuments({ owner });
        if(count >= 5) return res.json({ success: false, message: "Max 5 Bots allowed." });

        const extractedId = getClientIdFromToken(token);
        if (!extractedId) return res.json({ success: false, message: "Invalid Bot Token Format." });

        const newBot = new BotModel({ 
            owner, 
            token,
            clientId: extractedId, 
            botUsername: "Connecting...", 
            isConnected: false
        });
        await newBot.save();

        const client = await startBot(newBot);
        
        if(client) {
            res.json({ success: true });
        } else {
            await BotModel.findByIdAndDelete(newBot._id);
            res.json({ success: false, message: "Invalid Token or Connection Failed." });
        }
    } catch(e) { 
        res.json({ success: false, message: "Error connecting bot." }); 
    }
});

app.post('/api/bots/delete', async (req, res) => {
    try {
        const { owner, id } = req.body;
        if(activeBots.has(id)) {
            const client = activeBots.get(id);
            client.destroy();
            activeBots.delete(id);
        }
        await BotModel.findOneAndDelete({ _id: id, owner });
        res.json({ success: true });
    } catch(e) { res.json({ success: false }); }
});

// Update Bot Config (Loadstring)
app.post('/api/bots/config', async (req, res) => {
    try {
        const { owner, botId, scriptLoadstring } = req.body;
        const bot = await BotModel.findOne({ _id: botId, owner });
        if(!bot) return res.json({ success: false, message: "Bot not found" });

        bot.config.scriptLoadstring = scriptLoadstring;
        await bot.save();
        res.json({ success: true });
    } catch(e) { res.json({ success: false }); }
});

// Get Bot Details
app.get('/api/bots/details/:id', async (req, res) => {
    try {
        const bot = await BotModel.findById(req.params.id);
        if(!bot) return res.json({});
        
        const client = activeBots.get(bot._id.toString());
        const guilds = client ? client.guilds.cache.map(g => g.name) : [];
        
        res.json({
            guilds: guilds,
            ping: client ? client.ws.ping : 0,
            status: client ? "Connected" : "Disconnected",
            inviteUrl: `https://discord.com/api/oauth2/authorize?client_id=${bot.clientId}&permissions=8&scope=bot%20applications.commands`,
            linkedAppId: bot.config.linkedAppId || "Not Configured",
            scriptLoadstring: bot.config.scriptLoadstring || ""
        });
    } catch(e) { res.json({}); }
});

// --- NEW: PROTECTED SCRIPT ENDPOINT (FIXED) ---
// Fetches the code server-side and returns raw LUA to the client.
app.get('/api/lua/protected-script', async (req, res) => {
    const { botId, key } = req.query;
    const userAgent = req.headers['user-agent'] || "";

    // 1. SECURITY: Basic User Agent Check (Must contain Roblox)
    // Prevents standard browsers. Python spoofing is mitigated by Key requirement below.
    if (!userAgent.includes("Roblox")) {
        return res.status(403).send("print('Access Denied: Roblox Executor Required.')");
    }

    try {
        // 2. Validate Bot and Config
        const bot = await BotModel.findById(botId);
        if(!bot || !bot.config.scriptLoadstring) {
            return res.status(404).send("print('Error: Script not configured in Dashboard.')");
        }

        // 3. Validate Key (Strict Check)
        // A Python dumper *could* spoof the UA, but they would need a VALID, ACTIVE Key linked to this App.
        // If they dump it, they burn a valid key.
        const keyData = await KeyModel.findOne({ key });
        
        if(!keyData) return res.status(403).send("print('Error: Invalid Key.')");
        if(!keyData.active) return res.status(403).send("print('Error: Key is Banned.')");
        if(keyData.expiresAt && new Date() > new Date(keyData.expiresAt)) return res.status(403).send("print('Error: Key Expired.')");
        
        // Ensure Key belongs to the App linked to this Bot
        if(bot.config.linkedAppId && keyData.appId !== bot.config.linkedAppId) {
            return res.status(403).send("print('Error: Key does not belong to this Application.')");
        }

        // 4. SERVER-SIDE FETCH (The Fix)
        // instead of sending "loadstring(url)", the server downloads the code and sends it.
        // This hides the real URL from the user and prevents the "nil value" error.
        
        let finalScript = "";

        if (bot.config.scriptLoadstring.startsWith("http")) {
            // It is a URL (GitHub, Pastebin, etc.) -> Fetch it
            try {
                const response = await axios.get(bot.config.scriptLoadstring);
                finalScript = response.data; // The raw Lua code
                
                // Optional: Check if response is an object (JSON) instead of text
                if (typeof finalScript === 'object') {
                    finalScript = JSON.stringify(finalScript);
                }
            } catch (fetchErr) {
                console.error("Fetch Error:", fetchErr.message);
                return res.status(500).send("print('Server Error: Could not fetch script source. Check URL in Dashboard.')");
            }
        } else {
            // It is raw code pasted directly into the dashboard input
            finalScript = bot.config.scriptLoadstring;
        }

        // 5. Send RAW Lua
        // The executor does: loadstring(game:HttpGet(THIS_ENDPOINT))()
        // THIS_ENDPOINT returns: print("Hello World")
        // Result: loadstring('print("Hello World")')() -> Works!
        res.setHeader('Content-Type', 'text/plain');
        res.send(finalScript);

    } catch(e) {
        console.error("Protected Endpoint Error:", e);
        res.status(500).send("print('Internal Server Error')");
    }
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
