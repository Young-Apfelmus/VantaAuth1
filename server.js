// server.js - DAS BACKEND
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const path = require('path');

const app = express();
const PORT = 3000; // Oder process.env.PORT für Cloudflare/Render

app.use(cors());
app.use(bodyParser.json());
//app.use(express.static('public')); // Frontend Dateien bereitstellen

// --- MOCK DATABASE (Später durch MongoDB/SQL ersetzen) ---
let users = []; // { username, passwordHash, role, hwid }
let keys = [];  // { key, generatedBy, usedBy, hwid, expires, scriptContent }
let scripts = []; // { id, name, content, owner }

// --- AUTH ROUTEN ---

// Register
app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;
    if (users.find(u => u.username === username)) {
        return res.json({ success: false, message: "User exists already." });
    }
    // Passwort verschlüsseln (Hashing)
    const hashedPassword = await bcrypt.hash(password, 10);
    
    users.push({ 
        username, 
        password: hashedPassword, 
        role: username === "LucaGamingFan1234" ? "owner" : "user" // Auto-Owner Logic
    });
    
    res.json({ success: true, message: "Registered successfully!" });
});

// Login
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    const user = users.find(u => u.username === username);
    
    if (!user) return res.json({ success: false, message: "User not found." });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.json({ success: false, message: "Wrong password." });

    res.json({ success: true, username: user.username, role: user.role });
});

// --- KEY MANAGEMENT ROUTEN ---

// Key erstellen (Nur im Dashboard)
app.post('/api/create-key', (req, res) => {
    const { owner, duration } = req.body; // duration in days
    
    // Generiere Vanta-Style Key
    const keyPart = Math.random().toString(36).substring(2, 8).toUpperCase();
    const newKey = `VNT-${keyPart}-PREM`;
    
    keys.push({
        key: newKey,
        generatedBy: owner,
        usedBy: null,
        hwid: null,
        active: true,
        expires: "Lifetime" // Vereinfacht für Demo
    });

    res.json({ success: true, key: newKey });
});

// Scripts abrufen
app.get('/api/scripts', (req, res) => {
    // Hier würde man nur Scripts senden, die dem User gehören
    res.json(scripts); 
});

// Neues Script speichern
app.post('/api/save-script', (req, res) => {
    const { name, content, owner } = req.body;
    scripts.push({ id: Date.now(), name, content, owner });
    res.json({ success: true, message: "Script saved." });
});

// --- NEUE ROUTE: LUA LOADER ---
// Das hier sendet das ECHTE Lua Script an den Client
app.get('/api/lua/loader', (req, res) => {
    const luaScript = `
local VantaAuth = {}
local HttpService = game:GetService("HttpService")

function VantaAuth:RedeemKey(key)
    local url = "https://vantaauth1.onrender.com/api/lua/verify" -- Deine URL
    
    -- HWID automatisch ermitteln
    local hwid = game:GetService("RbxAnalyticsService"):GetClientId()
    
    -- Request Body bauen
    local body = HttpService:JSONEncode({
        key = key,
        hwid = hwid
    })

    -- Den Request senden (POST)
    local response = request({
        Url = url,
        Method = "POST",
        Headers = {
            ["Content-Type"] = "application/json"
        },
        Body = body
    })

    if response.StatusCode == 200 then
        local data = HttpService:JSONDecode(response.Body)
        if data.valid then
            print("VantaAuth: Success!")
            -- Hier führen wir das geschützte Script aus, das der Server schickt
            loadstring(data.script)() 
        else
            warn("VantaAuth: " .. (data.message or "Invalid Key"))
            game.Players.LocalPlayer:Kick("Invalid Key")
        end
    else
        warn("VantaAuth: Server Error " .. response.StatusCode)
    end
end

return VantaAuth
    `;
    
    res.send(luaScript);
});


// --- LUA API ENDPOINT (Das hier nutzt das Roblox Script) ---
// Checkt: Stimmt Key? Stimmt HWID?
app.post('/api/lua/verify', (req, res) => {
    const { key, hwid } = req.body;
    
    const keyData = keys.find(k => k.key === key);
    
    if (!keyData) {
        return res.json({ valid: false, message: "Key not found" });
    }

    if (!keyData.active) {
        return res.json({ valid: false, message: "Key blacklisted" });
    }

    // Wenn Key noch unbenutzt, binde HWID (Linken)
    if (!keyData.hwid) {
        keyData.hwid = hwid;
        keyData.usedBy = "RedeemedUser"; // Hier könnte man Usernamen loggen
    } else {
        // Wenn Key benutzt, prüfe ob HWID stimmt
        if (keyData.hwid !== hwid) {
            return res.json({ valid: false, message: "Invalid HWID" });
        }
    }

    res.json({ 
        valid: true, 
        message: "Authenticated", 
        script: `print('Welcome to VantaAuth!'); -- Hier Loadstring laden`
    });
});

// Server Starten
app.listen(PORT, () => {
    console.log(`VantaAuth Backend running on http://localhost:${PORT}`);
});
