const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const crypto = require('crypto'); // Neu für Secrets

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(bodyParser.json());

// --- DATABASE ---
let users = []; 
let apps = []; // Neu: { id, name, owner, secret }
let keys = []; // Update: { key, appId, ... }
let scripts = [];

// --- HELPER ---
function generateId(length) {
    return crypto.randomBytes(length).toString('hex').slice(0, length);
}

// --- AUTH ROUTEN ---
app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;
    if (users.find(u => u.username === username)) return res.json({ success: false, message: "Taken." });
    const hashedPassword = await bcrypt.hash(password, 10);
    users.push({ username, password: hashedPassword, role: "user" }); // Erster User könnte Owner sein
    res.json({ success: true });
});

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    const user = users.find(u => u.username === username);
    if (!user || !(await bcrypt.compare(password, user.password))) return res.json({ success: false, message: "Invalid credentials" });
    res.json({ success: true, username: user.username });
});

// --- APP MANAGEMENT (NEU) ---
app.post('/api/create-app', (req, res) => {
    const { name, owner } = req.body;
    const appId = generateId(10);     // Z.B. "a1b2c3d4e5"
    const secret = generateId(32);    // Langes Secret für Sicherheit
    
    apps.push({ id: appId, name, owner, secret });
    res.json({ success: true, app: { id: appId, name, secret } });
});

app.get('/api/my-apps', (req, res) => {
    const { owner } = req.query;
    const myApps = apps.filter(a => a.owner === owner);
    res.json(myApps);
});

// --- KEY MANAGEMENT ---
app.post('/api/create-key', (req, res) => {
    const { owner, appId, duration } = req.body;
    
    // Prüfen ob App existiert
    const application = apps.find(a => a.id === appId);
    if (!application) return res.json({ success: false, message: "App not found" });

    const keyPart = Math.random().toString(36).substring(2, 8).toUpperCase();
    const newKey = `VNT-${keyPart}-PREM`;
    
    keys.push({
        key: newKey,
        appId: appId, // WICHTIG: Key gehört jetzt zu dieser App
        appName: application.name,
        generatedBy: owner,
        hwid: null,
        active: true
    });

    res.json({ success: true, key: newKey });
});

app.get('/api/my-keys', (req, res) => {
    // Hier könnten wir filtern
    res.json(keys);
});

// --- LUA API (UPDATED) ---
app.get('/api/lua/loader', (req, res) => {
    // Der Loader akzeptiert jetzt App-Daten
    const luaScript = `
local VantaAuth = {}
local HttpService = game:GetService("HttpService")
local StarterGui = game:GetService("StarterGui")

function VantaAuth.Login(appId, appSecret, key)
    local url = "https://vantaauth1.onrender.com/api/lua/verify"
    local hwid = game:GetService("RbxAnalyticsService"):GetClientId()
    
    local body = HttpService:JSONEncode({
        appId = appId,
        appSecret = appSecret,
        key = key,
        hwid = hwid
    })

    local response = request({
        Url = url,
        Method = "POST",
        Headers = { ["Content-Type"] = "application/json" },
        Body = body
    })

    if response.StatusCode == 200 then
        local data = HttpService:JSONDecode(response.Body)
        if data.valid then
            
            StarterGui:SetCore("SendNotification", {
                Title = "VantaAuth",
                Text = "Login Successful!",
                Duration = 5
            })
            
            -- Geschütztes Script ausführen
            loadstring(data.script)()
        else
            game.Players.LocalPlayer:Kick("Auth Failed: " .. (data.message or "Unknown"))
        end
    else
        warn("Connection Error")
    end
end

return VantaAuth
    `;
    res.send(luaScript);
});

app.post('/api/lua/verify', (req, res) => {
    const { appId, appSecret, key, hwid } = req.body;
    
    // 1. App Check
    const appData = apps.find(a => a.id === appId);
    if (!appData) return res.json({ valid: false, message: "Invalid Application ID" });
    if (appData.secret !== appSecret) return res.json({ valid: false, message: "Invalid App Secret" });

    // 2. Key Check
    const keyData = keys.find(k => k.key === key);
    if (!keyData) return res.json({ valid: false, message: "Key not found" });

    // 3. Cross-Check: Gehört der Key zur App?
    if (keyData.appId !== appId) return res.json({ valid: false, message: "Key belongs to another app" });

    // 4. HWID Logic
    if (!keyData.active) return res.json({ valid: false, message: "Key Blacklisted" });
    
    if (!keyData.hwid) {
        keyData.hwid = hwid; // Link HWID
    } else if (keyData.hwid !== hwid) {
        return res.json({ valid: false, message: "Invalid HWID" });
    }

    res.json({ 
        valid: true, 
        script: `print("Hello from ${appData.name}!")` // Hier später echtes Skript laden
    });
});

app.listen(PORT, () => console.log(`Server on ${PORT}`));
