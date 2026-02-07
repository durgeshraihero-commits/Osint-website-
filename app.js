// ==================== CONFIGURATION ====================
const API_BASE_URL = window.location.origin;
const TELEGRAM_ADMIN = 'https://t.me/darkboxesAdmin';
const TELEGRAM_BOT = 'https://t.me/darkboxes_bot';

// ==================== STATE MANAGEMENT ====================
let currentUser = null;
let authToken = null;
let commands = [];
let plans = [];
let selectedCommand = null;

// ==================== MATRIX RAIN EFFECT ====================
function initMatrixRain() {
    const canvas = document.getElementById('matrix-canvas');
    const ctx = canvas.getContext('2d');
    
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
    
    const chars = '01アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヲン';
    const fontSize = 14;
    const columns = canvas.width / fontSize;
    const drops = Array(Math.floor(columns)).fill(1);
    
    function draw() {
        ctx.fillStyle = 'rgba(10, 14, 39, 0.05)';
        ctx.fillRect(0, 0, canvas.width, canvas.height);
        
        ctx.fillStyle = '#00ff41';
        ctx.font = fontSize + 'px monospace';
        
        for (let i = 0; i < drops.length; i++) {
            const text = chars[Math.floor(Math.random() * chars.length)];
            ctx.fillText(text, i * fontSize, drops[i] * fontSize);
            
            if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) {
                drops[i] = 0;
            }
            drops[i]++;
        }
    }
    
    setInterval(draw, 33);
    
    window.addEventListener('resize', () => {
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
    });
}

// ==================== TERMINAL DEMO ====================
function initTerminalDemo() {
    const terminal = document.getElementById('terminal-demo');
    const commands = [
        '> darkboxes --init',
        '[ ✓ ] System initialized',
        '[ ✓ ] Loading intelligence modules...',
        '[ ✓ ] 14 modules loaded successfully',
        '> darkboxes --search phone 9876543210',
        '[ ⟳ ] Searching database...',
        '[ ✓ ] Match found: Name, Address, Carrier',
        '> darkboxes --status',
        '[ ✓ ] System: OPERATIONAL',
        '[ ✓ ] Security: MAXIMUM',
        '> _'
    ];
    
    let i = 0;
    function typeLine() {
        if (i < commands.length) {
            const line = document.createElement('div');
            line.className = 'terminal-line';
            line.textContent = commands[i];
            line.style.animationDelay = `${i * 0.1}s`;
            terminal.appendChild(line);
            i++;
            setTimeout(typeLine, 800);
        } else {
            setTimeout(() => {
                terminal.innerHTML = '';
                i = 0;
                typeLine();
            }, 3000);
        }
    }
    typeLine();
}

// ==================== LEGAL DISCLAIMER ====================
function initLegalDisclaimer() {
    const hasAccepted = localStorage.getItem('darkboxes_legal_accepted');
    
    if (!hasAccepted) {
        showLegalModal();
    }
    
    document.getElementById('legal-consent').addEventListener('change', (e) => {
        document.getElementById('accept-terms').disabled = !e.target.checked;
    });
    
    document.getElementById('accept-terms').addEventListener('click', () => {
        localStorage.setItem('darkboxes_legal_accepted', 'true');
        hideLegalModal();
    });
    
    document.getElementById('decline-terms').addEventListener('click', () => {
        window.location.href = 'about:blank';
    });
}

function showLegalModal() {
    document.getElementById('legal-modal').classList.add('active');
}

function hideLegalModal() {
    document.getElementById('legal-modal').classList.remove('active');
}

// ==================== BROADCASTS ====================
async function loadBroadcasts() {
    try {
        const response = await fetch(`${API_BASE_URL}/api/broadcasts/active`);
        const result = await response.json();
        
        if (result.status === 'success' && result.data.length > 0) {
            const container = document.getElementById('broadcast-container');
            container.innerHTML = '';
            
            result.data.forEach(broadcast => {
                const alert = document.createElement('div');
                alert.className = `alert alert-${broadcast.type} broadcast-message`;
                alert.innerHTML = `
                    <i class="fas fa-bullhorn"></i>
                    <span>${broadcast.message}</span>
                `;
                container.appendChild(alert);
            });
        }
    } catch (error) {
        console.error('Failed to load broadcasts:', error);
    }
}

// ==================== AUTHENTICATION ====================
function checkAuth() {
    authToken = localStorage.getItem('darkboxes_token');
    
    if (authToken) {
        loadUserProfile();
    } else {
        showGuestUI();
    }
}

async function loadUserProfile() {
    try {
        const response = await fetch(`${API_BASE_URL}/api/user/profile`, {
            headers: {
                'Authorization': `Bearer ${authToken}`
            }
        });
        
        if (response.ok) {
            const result = await response.json();
            currentUser = result.data;
            showUserUI();
            
            if (currentUser.isAdmin) {
                document.getElementById('admin-nav').style.display = 'block';
            }
        } else {
            logout();
        }
    } catch (error) {
        console.error('Failed to load profile:', error);
        logout();
    }
}

function showGuestUI() {
    document.getElementById('auth-buttons').style.display = 'flex';
    document.getElementById('user-menu').style.display = 'none';
    document.getElementById('login-required').style.display = 'block';
    document.getElementById('search-interface').style.display = 'none';
}

function showUserUI() {
    document.getElementById('auth-buttons').style.display = 'none';
    document.getElementById('user-menu').style.display = 'flex';
    document.getElementById('user-name').textContent = currentUser.username;
    document.getElementById('user-credits').textContent = `${currentUser.credits} Credits`;
    document.getElementById('login-required').style.display = 'none';
    document.getElementById('search-interface').style.display = 'block';
}

async function login(username, password) {
    try {
        showLoading();
        const response = await fetch(`${API_BASE_URL}/api/auth/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        
        const result = await response.json();
        hideLoading();
        
        if (result.status === 'success') {
            authToken = result.data.token;
            localStorage.setItem('darkboxes_token', authToken);
            currentUser = result.data.user;
            showUserUI();
            hideModal('login-modal');
            showAlert('Login successful!', 'success');
            
            if (currentUser.isAdmin) {
                document.getElementById('admin-nav').style.display = 'block';
            }
        } else {
            showAlert(result.message || 'Login failed', 'error');
        }
    } catch (error) {
        hideLoading();
        showAlert('Login failed. Please try again.', 'error');
    }
}

async function register(username, email, password) {
    try {
        showLoading();
        const response = await fetch(`${API_BASE_URL}/api/auth/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, email, password })
        });
        
        const result = await response.json();
        hideLoading();
        
        if (result.status === 'success') {
            hideModal('register-modal');
            showAlert(result.message || 'Registration successful! Please login.', 'success');
            setTimeout(() => showModal('login-modal'), 1000);
        } else {
            showAlert(result.message || 'Registration failed', 'error');
        }
    } catch (error) {
        hideLoading();
        showAlert('Registration failed. Please try again.', 'error');
    }
}

function logout() {
    localStorage.removeItem('darkboxes_token');
    authToken = null;
    currentUser = null;
    document.getElementById('admin-nav').style.display = 'none';
    showGuestUI();
    showAlert('Logged out successfully', 'info');
}

// ==================== COMMANDS ====================
async function loadCommands() {
    try {
        const response = await fetch(`${API_BASE_URL}/api/commands`, {
            headers: authToken ? { 'Authorization': `Bearer ${authToken}` } : {}
        });
        
        const result = await response.json();
        
        if (result.status === 'success') {
            commands = result.data;
            renderCommands();
        }
    } catch (error) {
        console.error('Failed to load commands:', error);
    }
}

function renderCommands() {
    const container = document.getElementById('search-commands');
    container.innerHTML = '';
    
    commands.forEach(cmd => {
        const card = document.createElement('div');
        card.className = `command-card ${!cmd.isEnabled ? 'disabled' : ''}`;
        card.innerHTML = `
            <h3>
                <i class="fas fa-terminal"></i> ${cmd.name}
                <span class="credit-badge">${cmd.creditCost} CR</span>
            </h3>
            <p>${cmd.description || 'Search ' + cmd.name + ' information'}</p>
        `;
        
        if (cmd.isEnabled) {
            card.addEventListener('click', () => selectCommand(cmd));
        }
        
        container.appendChild(card);
    });
}

function selectCommand(cmd) {
    selectedCommand = cmd;
    
    // Update UI
    document.querySelectorAll('.command-card').forEach(card => {
        card.classList.remove('active');
    });
    event.target.closest('.command-card').classList.add('active');
    
    // Show form
    document.getElementById('search-form-container').style.display = 'block';
    document.getElementById('selected-command-name').textContent = cmd.name.toUpperCase();
    document.getElementById('selected-command-desc').textContent = cmd.description || '';
    document.querySelector('.credit-cost').textContent = `(${cmd.creditCost} Credits)`;
    document.getElementById('search-query').value = '';
    document.getElementById('search-query').focus();
}

// ==================== SEARCH ====================
async function executeSearch() {
    if (!selectedCommand) return;
    
    const query = document.getElementById('search-query').value.trim();
    
    if (!query) {
        showAlert('Please enter a search query', 'warning');
        return;
    }
    
    try {
        showLoading();
        const response = await fetch(`${API_BASE_URL}/api/search/${selectedCommand.name}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${authToken}`
            },
            body: JSON.stringify({ query })
        });
        
        const result = await response.json();
        hideLoading();
        
        if (result.status === 'success') {
            displayResults(result.data);
            
            // Update credits
            currentUser.credits = result.creditsRemaining;
            document.getElementById('user-credits').textContent = `${currentUser.credits} Credits`;
            
            showAlert(`Search completed! ${result.creditsRemaining} credits remaining`, 'success');
        } else {
            showAlert(result.message || 'Search failed', 'error');
        }
    } catch (error) {
        hideLoading();
        showAlert('Search failed. Please try again.', 'error');
    }
}

function displayResults(data) {
    const container = document.getElementById('search-results');
    container.innerHTML = '<h3><i class="fas fa-database"></i> Search Results</h3>';
    
    if (typeof data === 'object' && data !== null) {
        const resultItem = document.createElement('div');
        resultItem.className = 'result-item';
        resultItem.innerHTML = formatJSON(data);
        container.appendChild(resultItem);
    } else if (typeof data === 'string') {
        container.innerHTML += `<div class="result-item">${data}</div>`;
    } else {
        container.innerHTML += '<div class="result-item">No results found</div>';
    }
    
    container.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function formatJSON(obj, indent = 0) {
    let html = '';
    const spacing = '&nbsp;'.repeat(indent * 4);
    
    for (const [key, value] of Object.entries(obj)) {
        if (typeof value === 'object' && value !== null) {
            html += `${spacing}<strong>${key}:</strong><br>`;
            html += formatJSON(value, indent + 1);
        } else {
            html += `${spacing}<strong>${key}:</strong> ${value}<br>`;
        }
    }
    
    return html;
}

// ==================== PLANS ====================
async function loadPlans() {
    try {
        const response = await fetch(`${API_BASE_URL}/api/plans`);
        const result = await response.json();
        
        if (result.status === 'success') {
            plans = result.data;
            renderPlans();
        }
    } catch (error) {
        console.error('Failed to load plans:', error);
    }
}

function renderPlans() {
    const container = document.getElementById('plans-grid');
    container.innerHTML = '';
    
    plans.forEach(plan => {
        const card = document.createElement('div');
        card.className = 'plan-card';
        card.innerHTML = `
            <h3>${plan.name}</h3>
            <div class="plan-price">₹${plan.price}</div>
            <div class="plan-credits">${plan.credits} Credits</div>
            <a href="${TELEGRAM_ADMIN}" target="_blank" class="btn btn-primary">
                <i class="fab fa-telegram"></i> Buy Now
            </a>
        `;
        container.appendChild(card);
    });
}

// ==================== UI HELPERS ====================
function showModal(modalId) {
    document.getElementById(modalId).classList.add('active');
}

function hideModal(modalId) {
    document.getElementById(modalId).classList.remove('active');
}

function showLoading() {
    document.getElementById('loading-overlay').classList.add('active');
}

function hideLoading() {
    document.getElementById('loading-overlay').classList.remove('active');
}

function showAlert(message, type = 'info') {
    const existingAlerts = document.querySelectorAll('.temp-alert');
    existingAlerts.forEach(alert => alert.remove());
    
    const alert = document.createElement('div');
    alert.className = `alert alert-${type} temp-alert`;
    alert.style.position = 'fixed';
    alert.style.top = '100px';
    alert.style.right = '20px';
    alert.style.zIndex = '2000';
    alert.style.minWidth = '300px';
    
    const icon = type === 'success' ? 'check-circle' : 
                 type === 'error' ? 'exclamation-circle' :
                 type === 'warning' ? 'exclamation-triangle' : 'info-circle';
    
    alert.innerHTML = `<i class="fas fa-${icon}"></i> ${message}`;
    document.body.appendChild(alert);
    
    setTimeout(() => alert.remove(), 5000);
}

function scrollToSection(sectionId) {
    const element = document.getElementById(sectionId);
    if (element) {
        element.scrollIntoView({ behavior: 'smooth' });
        
        // Update active nav link
        document.querySelectorAll('.nav-link').forEach(link => {
            link.classList.remove('active');
            if (link.getAttribute('href') === '#' + sectionId) {
                link.classList.add('active');
            }
        });
    }
}

// ==================== EVENT LISTENERS ====================
document.addEventListener('DOMContentLoaded', () => {
    // Initialize
    initMatrixRain();
    initTerminalDemo();
    initLegalDisclaimer();
    checkAuth();
    loadBroadcasts();
    loadCommands();
    loadPlans();
    
    // Refresh broadcasts periodically
    setInterval(loadBroadcasts, 60000);
    
    // Navigation
    document.querySelectorAll('.nav-link').forEach(link => {
        link.addEventListener('click', (e) => {
            if (link.getAttribute('href').startsWith('#')) {
                e.preventDefault();
                const sectionId = link.getAttribute('href').substring(1);
                scrollToSection(sectionId);
            }
        });
    });
    
    // Auth buttons
    document.getElementById('login-btn').addEventListener('click', () => {
        showModal('login-modal');
    });
    
    document.getElementById('register-btn').addEventListener('click', () => {
        showModal('register-modal');
    });
    
    document.getElementById('logout-btn').addEventListener('click', logout);
    
    // Modal close buttons
    document.querySelectorAll('.modal-close').forEach(btn => {
        btn.addEventListener('click', () => {
            hideModal(btn.closest('.modal').id);
        });
    });
    
    // Click outside modal to close
    document.querySelectorAll('.modal').forEach(modal => {
        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                hideModal(modal.id);
            }
        });
    });
    
    // Login form
    document.getElementById('login-form').addEventListener('submit', (e) => {
        e.preventDefault();
        const username = document.getElementById('login-username').value;
        const password = document.getElementById('login-password').value;
        login(username, password);
    });
    
    // Register form
    document.getElementById('register-form').addEventListener('submit', (e) => {
        e.preventDefault();
        const username = document.getElementById('register-username').value;
        const email = document.getElementById('register-email').value;
        const password = document.getElementById('register-password').value;
        register(username, email, password);
    });
    
    // Search actions
    document.getElementById('execute-search').addEventListener('click', executeSearch);
    
    document.getElementById('cancel-search').addEventListener('click', () => {
        document.getElementById('search-form-container').style.display = 'none';
        selectedCommand = null;
        document.querySelectorAll('.command-card').forEach(card => {
            card.classList.remove('active');
        });
    });
    
    // Enter key to search
    document.getElementById('search-query').addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            executeSearch();
        }
    });
    
    // Admin panel toggle
    document.getElementById('admin-nav').addEventListener('click', (e) => {
        e.preventDefault();
        if (currentUser && currentUser.isAdmin) {
            document.getElementById('admin-panel').style.display = 'block';
            loadAdminDashboard();
        }
    });
    
    document.getElementById('close-admin').addEventListener('click', () => {
        document.getElementById('admin-panel').style.display = 'none';
    });
});
