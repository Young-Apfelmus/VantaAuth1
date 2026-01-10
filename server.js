require('dotenv').config(); // Falls du lokal testest
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

// --- DATABASE SCHEMAS (Struktur) ---

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

// Key Schema
const KeySchema = new mongoose.Schema({
    key: { type: String, unique: true },
    appId: String,
    appName: String,
    generatedBy: String,
    hwid: { type: String, default: null },
    ip: { type: String, default: null },
    active: { type: Boolean, default: true },
    createdAt: { type: Date, default: Date.now }
});
const KeyModel = mongoose.model('Key', KeySchema);

// Log Schema
const LogSchema = new mongoose.Schema({
    time: String,
    appId: String,
    appName: String,
    key: String,
    ip: String,
    message: String,
    createdAt: { type: Date, default: Date.now }
});
const LogModel = mongoose.model('Log', LogSchema);


// --- HELPER ---
function generateId(len) { return crypto.randomBytes(len).toString('hex').slice(0, len); }
function getTime() { return new Date().toISOString().replace('T', ' ').substring(0, 19); }


// --- AUTH ---
app.post('/api/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        // Prüfen ob User existiert (DB Anfrage)
        const existingUser = await User.findOne({ username });
        if (existingUser) return res.json({ success: false, message: "Taken" });

        const hashedPassword = await bcrypt.hash(password, 10);
        
        // Neuen User in DB speichern
        const newUser = new User({ username, password: hashedPassword });
        await newUser.save();

        res.json({ success: true });
    } catch (e) {
        console.error(e);
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
        console.error(e);
        res.status(500).json({ success: false });
    }
});


// --- APP MANAGEMENT ---
app.get('/api/my-apps', async (req, res) => {
    try {
        const { owner } = req.query;
        // Suche alle Apps des Owners in der DB
        const myApps = await AppModel.find({ owner });
        res.json(myApps);
    } catch (e) {
        res.json([]);
    }
});

app.post('/api/create-app', async (req, res) => {
    try {
        const { name, owner } = req.body;
        const appId = generateId(10);
        const secret = generateId(40); 
        
        const newApp = new AppModel({ 
            id: appId, 
            name, 
            owner, 
            secret, 
            totalUsers: 0, 
            onlineUsers: 0 
        });
        await newApp.save();

        res.json({ success: true });
    } catch (e) {
        res.json({ success: false });
    }
});


// --- KEY & LOGS ---
app.post('/api/create-key', async (req, res) => {
    try {
        const { owner, appId } = req.body;
        
        // App suchen
        const application = await AppModel.findOne({ id: appId });
        if(!application) return res.json({ success: false });

        const keyStr = `VNT-${generateId(4).toUpperCase()}-${generateId(4).toUpperCase()}`;
        
        const newKey = new KeyModel({
            key: keyStr,
            appId: appId,
            appName: application.name,
            generatedBy: owner,
            hwid: null,
            ip: null,
            active: true
        });
        await newKey.save();
        
        res.json({ success: true, key: keyStr });
    } catch (e) {
        res.json({ success: false });
    }
});

app.get('/api/dashboard-data', async (req, res) => {
    try {
        const { owner } = req.query;
        
        // 1. Alle App-IDs des Users finden
        const apps = await AppModel.find({ owner });
        const myAppIds = apps.map(a => a.id);
        
        // 2. Keys und Logs aus DB laden, die zu diesen Apps gehören
        // Sortierung: Neueste zuerst (createdAt: -1)
        const myKeys = await KeyModel.find({ appId: { $in: myAppIds } }).sort({ createdAt: -1 });
        const myLogs = await LogModel.find({ appId: { $in: myAppIds } }).sort({ createdAt: -1 }).limit(100);

        res.json({ keys: myKeys, logs: myLogs });
    } catch (e) {
        console.error(e);
        res.json({ keys: [], logs: [] });
    }
});


// --- LUA VERIFY (Das Herzstück) ---
app.get('/api/lua/loader', (req, res) => {
    // URL hardcoded wie im Original, aber dynamisch ist sicherer falls sich die Render URL ändert.
    // Ich lasse es so wie du es hattest.
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
        // 1. App Check
        const appData = await AppModel.findOne({ id: appId });
        if (!appData || appData.secret !== secret) return res.json({ valid: false, message: "Invalid App/Secret" });

        // 2. Key Check
        const keyData = await KeyModel.findOne({ key: key });
        if (!keyData) return res.json({ valid: false, message: "Invalid Key" });
        if (keyData.appId !== appId) return res.json({ valid: false, message: "Key not for this App" });
        if (!keyData.active) return res.json({ valid: false, message: "Key Banned" });

        // 3. HWID & IP Logic
        if (!keyData.hwid) {
            // Erster Login -> Binden
            keyData.hwid = hwid;
            keyData.ip = ip;
            await keyData.save();

            // Stats updaten
            appData.totalUsers += 1;
            await appData.save();
        } else if (keyData.hwid !== hwid) {
            // HWID Mismatch -> Loggen
            await LogModel.create({ time: getTime(), appId, appName: appData.name, key, ip, message: "HWID Mismatch Warning" });
            return res.json({ valid: false, message: "HWID Mismatch" });
        }

        // Erfolgreicher Login -> Loggen
        await LogModel.create({ time: getTime(), appId, appName: appData.name, key, ip, message: "Login Success" });
        
        res.json({ valid: true, script: `print("Hello ${key} from ${appData.name}")` });

    } catch (e) {
        console.error(e);
        res.json({ valid: false, message: "Server Error" });
    }
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
