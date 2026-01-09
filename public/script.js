let isLoginMode = true;
let currentUser = null;
const API_BASE_URL = "https://vanta-auth-production.up.railway.app";

// --- AUTH LOGIC ---
function toggleAuthMode() {
    isLoginMode = !isLoginMode;
    document.getElementById('auth-title').innerText = isLoginMode ? "Login to Dashboard" : "Create Account";
    document.getElementById('auth-btn').innerText = isLoginMode ? "Login" : "Register";
    document.querySelector('.toggle-auth').innerText = isLoginMode ? "No account? Register here" : "Have account? Login";
}

async function handleAuth() {
    const user = document.getElementById('username').value;
    const pass = document.getElementById('password').value;
    
    const endpoint = isLoginMode ? `${API_BASE_URL}/api/login` : `${API_BASE_URL}/api/register`;
    
    try {
        const response = await fetch(endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username: user, password: pass })
        });
        
        const data = await response.json();
        
        if (data.success) {
            if (isLoginMode) {
                currentUser = data.username;
                document.getElementById('display-username').innerText = currentUser;
                document.getElementById('auth-container').classList.add('hidden'); // CSS class 'hidden' {display:none}
                document.getElementById('dashboard-container').classList.remove('hidden');
                loadKeys(); // Lade Daten
            } else {
                alert("Registered! Please login now.");
                toggleAuthMode();
            }
        } else {
            alert(data.message);
        }
    } catch (e) {
        console.error(e);
        alert("Server Error. Is Node running?");
    }
}

// --- KEY LOGIC ---
async function createKey() {
    const res = await fetch('/api/create-key', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ owner: currentUser, duration: 30 })
    });
    const data = await res.json();
    if(data.success) {
        alert("Created Key: " + data.key);
        loadKeys(); // Refresh List
    }
}

function loadKeys() {
    // Hier würdest du normalerweise Keys vom Server fetchen.
    // Für Demo fügen wir den neuen Key einfach optisch hinzu.
    // In der echten App: fetch('/api/keys')...
    const list = document.getElementById('key-list');
    // Mockup Eintrag hinzufügen
    list.innerHTML += `<div class="script-card" style="margin-top:10px;"><h4>Recent Key</h4><p>Created by You</p></div>`;
}

// --- EDITOR LOGIC ---
function insertAPITemplate() {
    const template = `
-- VantaAuth Protected Script
local VantaLib = loadstring(game:HttpGet("http://localhost:3000/api/lua/loader"))()

VantaLib:Login("${currentUser}", "YOUR_PASSWORD") -- Wenn du User Login willst
-- ODER KEY AUTH
VantaLib:RedeemKey("VNT-XXXX-PREM")
`;
    document.getElementById('script-content').value = template;
}

async function saveScript() {
    const name = document.getElementById('script-name').value;
    const content = document.getElementById('script-content').value;
    
    await fetch('/api/save-script', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, content, owner: currentUser })
    });
    alert("Script saved to Secure Cloud!");
}

// Tabs
function openTab(id) {
    document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active-tab'));
    document.getElementById(id).classList.add('active-tab');
}