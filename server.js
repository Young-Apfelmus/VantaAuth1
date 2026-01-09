const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const crypto = require('crypto'); // Für Secrets

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(bodyParser.json());

// --- IN-MEMORY DATENBANK ---
let users = []; 
let apps = []; // { id, name, owner, secret, totalUsers, onlineUsers }
let keys = []; // { key, appId, generatedBy, hwid, ip, status }
let logs = []; // { time, appId, appName, key, ip, message }

// --- HELPER ---
function generateId(len) { return crypto.randomBytes(len).toString('hex').slice(0, len); }
function getTime() { return new Date().toISOString().replace('T', ' ').substring(0, 19); }

// --- AUTH ---
app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;
    if (users.find(u => u.username === username)) return res.json({ success: false, message: "Taken" });
    const hashedPassword = await bcrypt.hash(password, 10);
    users.push({ username, password: hashedPassword });
    res.json({ success: true });
});

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    const user = users.find(u => u.username === username);
    if (!user || !(await bcrypt.compare(password, user.password))) return res.json({ success: false });
    res.json({ success: true, username: user.username });
});

// --- APP MANAGEMENT ---
app.get('/api/my-apps', (req, res) => {
    const { owner } = req.query;
    // Wir senden Apps + deren Stats zurück
    const myApps = apps.filter(a => a.owner === owner);
    res.json(myApps);
});

app.post('/api/create-app', (req, res) => {
    const { name, owner } = req.body;
    const appId = generateId(10);
    const secret = generateId(40); // Langes Secret
    
    apps.push({ 
        id: appId, 
        name, 
        owner, 
        secret, 
        totalUsers: 0, 
        onlineUsers: 0 
    });
    res.json({ success: true });
});

// --- KEY & LOGS ---
app.post('/api/create-key', (req, res) => {
    const { owner, appId, duration } = req.body;
    const application = apps.find(a => a.id === appId);
    if(!application) return res.json({ success: false });

    const keyStr = `VNT-${generateId(4).toUpperCase()}-${generateId(4).toUpperCase()}`;
    
    keys.push({
        key: keyStr,
        appId: appId,
        appName: application.name,
        generatedBy: owner,
        hwid: null,
        ip: null,
        active: true
    });
    
    res.json({ success: true, key: keyStr });
});

// Gibt Keys UND Logs zurück
app.get('/api/dashboard-data', (req, res) => {
    const { owner } = req.query;
    // Filtern: Nur Daten, die dem User gehören (via Apps)
    const myAppIds = apps.filter(a => a.owner === owner).map(a => a.id);
    
    const myKeys = keys.filter(k => myAppIds.includes(k.appId));
    const myLogs = logs.filter(l => myAppIds.includes(l.appId)).reverse(); // Neueste zuerst

    res.json({ keys: myKeys, logs: myLogs });
});

// --- LUA VERIFY (Das Herzstück) ---
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

app.post('/api/lua/verify', (req, res) => {
    // IP vom Request holen (Render Header)
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    const { appId, secret, key, hwid } = req.body;

    // 1. App Check
    const appData = apps.find(a => a.id === appId);
    if (!appData || appData.secret !== secret) return res.json({ valid: false, message: "Invalid App/Secret" });

    // 2. Key Check
    const keyData = keys.find(k => k.key === key);
    if (!keyData) return res.json({ valid: false, message: "Invalid Key" });
    if (keyData.appId !== appId) return res.json({ valid: false, message: "Key not for this App" });
    if (!keyData.active) return res.json({ valid: false, message: "Key Banned" });

    // 3. HWID & IP Logic
    if (!keyData.hwid) {
        keyData.hwid = hwid;
        keyData.ip = ip;
        appData.totalUsers++; // Statistik hochzählen
    } else if (keyData.hwid !== hwid) {
        // Loggen des fehlgeschlagenen Versuchs
        logs.push({ time: getTime(), appId, appName: appData.name, key, ip, message: "HWID Mismatch Warning" });
        return res.json({ valid: false, message: "HWID Mismatch" });
    }

    // Erfolgreicher Login -> Loggen
    logs.push({ time: getTime(), appId, appName: appData.name, key, ip, message: "Login Success" });
    
    res.json({ valid: true, script: `print("Hello ${key} from ${appData.name}")` });
});

app.listen(PORT, () => console.log("Server running"));
