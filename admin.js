// ==================== ADMIN DASHBOARD ====================
async function loadAdminDashboard() {
    loadAdminStats();
    loadAdminUsers();
    loadAdminCommands();
    loadAdminPlans();
    loadAdminBroadcasts();
    loadAdminConfig();
    loadAdminLogs();
    
    // Tab switching
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const tab = btn.dataset.tab;
            switchAdminTab(tab);
        });
    });
    
    // Admin action buttons
    setupAdminActions();
}

function switchAdminTab(tabName) {
    // Update buttons
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.remove('active');
        if (btn.dataset.tab === tabName) {
            btn.classList.add('active');
        }
    });
    
    // Update content
    document.querySelectorAll('.tab-content').forEach(content => {
        content.classList.remove('active');
    });
    document.getElementById(`${tabName}-tab`).classList.add('active');
}

// ==================== ADMIN STATS ====================
async function loadAdminStats() {
    try {
        const response = await fetch(`${API_BASE_URL}/api/admin/stats`, {
            headers: { 'Authorization': `Bearer ${authToken}` }
        });
        
        const result = await response.json();
        
        if (result.status === 'success') {
            renderAdminStats(result.data);
        }
    } catch (error) {
        console.error('Failed to load stats:', error);
    }
}

function renderAdminStats(data) {
    const container = document.getElementById('admin-stats');
    container.innerHTML = `
        <div class="stat-card">
            <i class="fas fa-users"></i>
            <h3>${data.totalUsers}</h3>
            <p>Total Users</p>
        </div>
        <div class="stat-card">
            <i class="fas fa-user-check"></i>
            <h3>${data.activeUsers}</h3>
            <p>Active Users</p>
        </div>
        <div class="stat-card">
            <i class="fas fa-search"></i>
            <h3>${data.totalSearches}</h3>
            <p>Total Searches</p>
        </div>
        <div class="stat-card">
            <i class="fas fa-chart-line"></i>
            <h3>${data.todaySearches}</h3>
            <p>Today's Searches</p>
        </div>
    `;
    
    // Recent activity
    const activityList = document.getElementById('recent-activity-list');
    activityList.innerHTML = '';
    
    if (data.recentActivity && data.recentActivity.length > 0) {
        data.recentActivity.forEach(activity => {
            const item = document.createElement('div');
            item.className = 'result-item';
            item.innerHTML = `
                <strong>${activity.username || 'System'}</strong> - ${activity.action}<br>
                <small>${new Date(activity.timestamp).toLocaleString()}</small>
            `;
            activityList.appendChild(item);
        });
    } else {
        activityList.innerHTML = '<p>No recent activity</p>';
    }
}

// ==================== ADMIN USERS ====================
async function loadAdminUsers() {
    try {
        const response = await fetch(`${API_BASE_URL}/api/admin/users`, {
            headers: { 'Authorization': `Bearer ${authToken}` }
        });
        
        const result = await response.json();
        
        if (result.status === 'success') {
            renderAdminUsers(result.data);
        }
    } catch (error) {
        console.error('Failed to load users:', error);
    }
}

function renderAdminUsers(users) {
    const container = document.getElementById('users-table');
    
    let html = `
        <table>
            <thead>
                <tr>
                    <th>Username</th>
                    <th>Email</th>
                    <th>Credits</th>
                    <th>Status</th>
                    <th>Admin</th>
                    <th>Created</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
    `;
    
    users.forEach(user => {
        html += `
            <tr>
                <td>${user.username}</td>
                <td>${user.email}</td>
                <td>${user.credits}</td>
                <td>
                    <span style="color: ${user.isActive ? 'var(--success)' : 'var(--error)'}">
                        ${user.isActive ? 'Active' : 'Inactive'}
                    </span>
                </td>
                <td>${user.isAdmin ? '✓' : '-'}</td>
                <td>${new Date(user.createdAt).toLocaleDateString()}</td>
                <td>
                    <button class="btn btn-sm btn-primary" onclick="editUserCredits('${user._id}', ${user.credits})">
                        <i class="fas fa-coins"></i> Credits
                    </button>
                    <button class="btn btn-sm ${user.isActive ? 'btn-danger' : 'btn-secondary'}" 
                            onclick="toggleUser('${user._id}')">
                        <i class="fas fa-${user.isActive ? 'ban' : 'check'}"></i>
                    </button>
                </td>
            </tr>
        `;
    });
    
    html += '</tbody></table>';
    container.innerHTML = html;
}

async function editUserCredits(userId, currentCredits) {
    const newCredits = prompt(`Enter new credits amount (current: ${currentCredits}):`, currentCredits);
    
    if (newCredits !== null) {
        try {
            showLoading();
            const response = await fetch(`${API_BASE_URL}/api/admin/users/${userId}/credits`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${authToken}`
                },
                body: JSON.stringify({ credits: parseInt(newCredits) })
            });
            
            const result = await response.json();
            hideLoading();
            
            if (result.status === 'success') {
                showAlert('Credits updated successfully', 'success');
                loadAdminUsers();
            } else {
                showAlert(result.message || 'Failed to update credits', 'error');
            }
        } catch (error) {
            hideLoading();
            showAlert('Failed to update credits', 'error');
        }
    }
}

async function toggleUser(userId) {
    if (confirm('Are you sure you want to toggle this user\'s status?')) {
        try {
            showLoading();
            const response = await fetch(`${API_BASE_URL}/api/admin/users/${userId}/toggle`, {
                method: 'POST',
                headers: { 'Authorization': `Bearer ${authToken}` }
            });
            
            const result = await response.json();
            hideLoading();
            
            if (result.status === 'success') {
                showAlert('User status updated', 'success');
                loadAdminUsers();
            } else {
                showAlert(result.message || 'Failed to update user', 'error');
            }
        } catch (error) {
            hideLoading();
            showAlert('Failed to update user', 'error');
        }
    }
}

// ==================== ADMIN COMMANDS ====================
async function loadAdminCommands() {
    try {
        const response = await fetch(`${API_BASE_URL}/api/admin/commands`, {
            headers: { 'Authorization': `Bearer ${authToken}` }
        });
        
        const result = await response.json();
        
        if (result.status === 'success') {
            renderAdminCommands(result.data);
        }
    } catch (error) {
        console.error('Failed to load commands:', error);
    }
}

function renderAdminCommands(commands) {
    const container = document.getElementById('commands-table');
    
    let html = `
        <table>
            <thead>
                <tr>
                    <th>Name</th>
                    <th>Endpoint</th>
                    <th>Cost</th>
                    <th>Status</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
    `;
    
    commands.forEach(cmd => {
        html += `
            <tr>
                <td>${cmd.name}</td>
                <td>${cmd.endpoint}</td>
                <td>${cmd.creditCost} CR</td>
                <td>
                    <span style="color: ${cmd.isEnabled ? 'var(--success)' : 'var(--error)'}">
                        ${cmd.isEnabled ? 'Enabled' : 'Disabled'}
                    </span>
                </td>
                <td>
                    <button class="btn btn-sm btn-primary" onclick="editCommand('${cmd._id}')">
                        <i class="fas fa-edit"></i>
                    </button>
                    <button class="btn btn-sm btn-danger" onclick="deleteCommand('${cmd._id}')">
                        <i class="fas fa-trash"></i>
                    </button>
                </td>
            </tr>
        `;
    });
    
    html += '</tbody></table>';
    container.innerHTML = html;
}

async function addCommand() {
    const name = prompt('Command name:');
    if (!name) return;
    
    const endpoint = prompt('API endpoint:');
    if (!endpoint) return;
    
    const creditCost = prompt('Credit cost:', '1');
    if (!creditCost) return;
    
    const description = prompt('Description (optional):');
    
    try {
        showLoading();
        const response = await fetch(`${API_BASE_URL}/api/admin/commands`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${authToken}`
            },
            body: JSON.stringify({
                name,
                endpoint,
                creditCost: parseInt(creditCost),
                description,
                isEnabled: true
            })
        });
        
        const result = await response.json();
        hideLoading();
        
        if (result.status === 'success') {
            showAlert('Command created successfully', 'success');
            loadAdminCommands();
        } else {
            showAlert(result.message || 'Failed to create command', 'error');
        }
    } catch (error) {
        hideLoading();
        showAlert('Failed to create command', 'error');
    }
}

async function editCommand(commandId) {
    // Simple edit - in production you'd want a proper modal
    const creditCost = prompt('New credit cost:');
    if (creditCost === null) return;
    
    const isEnabled = confirm('Enable this command?');
    
    try {
        showLoading();
        const response = await fetch(`${API_BASE_URL}/api/admin/commands/${commandId}`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${authToken}`
            },
            body: JSON.stringify({
                creditCost: parseInt(creditCost),
                isEnabled
            })
        });
        
        const result = await response.json();
        hideLoading();
        
        if (result.status === 'success') {
            showAlert('Command updated successfully', 'success');
            loadAdminCommands();
            loadCommands(); // Refresh user commands
        } else {
            showAlert(result.message || 'Failed to update command', 'error');
        }
    } catch (error) {
        hideLoading();
        showAlert('Failed to update command', 'error');
    }
}

async function deleteCommand(commandId) {
    if (confirm('Are you sure you want to delete this command?')) {
        try {
            showLoading();
            const response = await fetch(`${API_BASE_URL}/api/admin/commands/${commandId}`, {
                method: 'DELETE',
                headers: { 'Authorization': `Bearer ${authToken}` }
            });
            
            const result = await response.json();
            hideLoading();
            
            if (result.status === 'success') {
                showAlert('Command deleted successfully', 'success');
                loadAdminCommands();
            } else {
                showAlert(result.message || 'Failed to delete command', 'error');
            }
        } catch (error) {
            hideLoading();
            showAlert('Failed to delete command', 'error');
        }
    }
}

// ==================== ADMIN PLANS ====================
async function loadAdminPlans() {
    try {
        const response = await fetch(`${API_BASE_URL}/api/admin/plans`, {
            headers: { 'Authorization': `Bearer ${authToken}` }
        });
        
        const result = await response.json();
        
        if (result.status === 'success') {
            renderAdminPlans(result.data);
        }
    } catch (error) {
        console.error('Failed to load plans:', error);
    }
}

function renderAdminPlans(plans) {
    const container = document.getElementById('plans-table');
    
    let html = `
        <table>
            <thead>
                <tr>
                    <th>Name</th>
                    <th>Credits</th>
                    <th>Price (₹)</th>
                    <th>Status</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
    `;
    
    plans.forEach(plan => {
        html += `
            <tr>
                <td>${plan.name}</td>
                <td>${plan.credits}</td>
                <td>₹${plan.price}</td>
                <td>
                    <span style="color: ${plan.isActive ? 'var(--success)' : 'var(--error)'}">
                        ${plan.isActive ? 'Active' : 'Inactive'}
                    </span>
                </td>
                <td>
                    <button class="btn btn-sm btn-primary" onclick="editPlan('${plan._id}')">
                        <i class="fas fa-edit"></i>
                    </button>
                    <button class="btn btn-sm btn-danger" onclick="deletePlan('${plan._id}')">
                        <i class="fas fa-trash"></i>
                    </button>
                </td>
            </tr>
        `;
    });
    
    html += '</tbody></table>';
    container.innerHTML = html;
}

async function addPlan() {
    const name = prompt('Plan name:');
    if (!name) return;
    
    const credits = prompt('Credits:');
    if (!credits) return;
    
    const price = prompt('Price (₹):');
    if (!price) return;
    
    try {
        showLoading();
        const response = await fetch(`${API_BASE_URL}/api/admin/plans`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${authToken}`
            },
            body: JSON.stringify({
                name,
                credits: parseInt(credits),
                price: parseInt(price),
                isActive: true
            })
        });
        
        const result = await response.json();
        hideLoading();
        
        if (result.status === 'success') {
            showAlert('Plan created successfully', 'success');
            loadAdminPlans();
            loadPlans(); // Refresh user plans
        } else {
            showAlert(result.message || 'Failed to create plan', 'error');
        }
    } catch (error) {
        hideLoading();
        showAlert('Failed to create plan', 'error');
    }
}

async function editPlan(planId) {
    const price = prompt('New price (₹):');
    if (price === null) return;
    
    const isActive = confirm('Make this plan active?');
    
    try {
        showLoading();
        const response = await fetch(`${API_BASE_URL}/api/admin/plans/${planId}`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${authToken}`
            },
            body: JSON.stringify({
                price: parseInt(price),
                isActive
            })
        });
        
        const result = await response.json();
        hideLoading();
        
        if (result.status === 'success') {
            showAlert('Plan updated successfully', 'success');
            loadAdminPlans();
            loadPlans();
        } else {
            showAlert(result.message || 'Failed to update plan', 'error');
        }
    } catch (error) {
        hideLoading();
        showAlert('Failed to update plan', 'error');
    }
}

async function deletePlan(planId) {
    if (confirm('Are you sure you want to delete this plan?')) {
        try {
            showLoading();
            const response = await fetch(`${API_BASE_URL}/api/admin/plans/${planId}`, {
                method: 'DELETE',
                headers: { 'Authorization': `Bearer ${authToken}` }
            });
            
            const result = await response.json();
            hideLoading();
            
            if (result.status === 'success') {
                showAlert('Plan deleted successfully', 'success');
                loadAdminPlans();
            } else {
                showAlert(result.message || 'Failed to delete plan', 'error');
            }
        } catch (error) {
            hideLoading();
            showAlert('Failed to delete plan', 'error');
        }
    }
}

// ==================== ADMIN BROADCASTS ====================
async function loadAdminBroadcasts() {
    try {
        const response = await fetch(`${API_BASE_URL}/api/admin/broadcasts`, {
            headers: { 'Authorization': `Bearer ${authToken}` }
        });
        
        const result = await response.json();
        
        if (result.status === 'success') {
            renderAdminBroadcasts(result.data);
        }
    } catch (error) {
        console.error('Failed to load broadcasts:', error);
    }
}

function renderAdminBroadcasts(broadcasts) {
    const container = document.getElementById('broadcasts-table');
    
    let html = `
        <table>
            <thead>
                <tr>
                    <th>Message</th>
                    <th>Type</th>
                    <th>Start Time</th>
                    <th>End Time</th>
                    <th>Status</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
    `;
    
    broadcasts.forEach(broadcast => {
        const now = new Date();
        const isActive = broadcast.isActive && 
                        new Date(broadcast.startTime) <= now && 
                        new Date(broadcast.endTime) >= now;
        
        html += `
            <tr>
                <td>${broadcast.message.substring(0, 50)}...</td>
                <td>${broadcast.type}</td>
                <td>${new Date(broadcast.startTime).toLocaleString()}</td>
                <td>${new Date(broadcast.endTime).toLocaleString()}</td>
                <td>
                    <span style="color: ${isActive ? 'var(--success)' : 'var(--error)'}">
                        ${isActive ? 'Active' : 'Inactive'}
                    </span>
                </td>
                <td>
                    <button class="btn btn-sm btn-primary" onclick="editBroadcast('${broadcast._id}')">
                        <i class="fas fa-edit"></i>
                    </button>
                    <button class="btn btn-sm btn-danger" onclick="deleteBroadcast('${broadcast._id}')">
                        <i class="fas fa-trash"></i>
                    </button>
                </td>
            </tr>
        `;
    });
    
    html += '</tbody></table>';
    container.innerHTML = html;
}

async function addBroadcast() {
    const message = prompt('Broadcast message:');
    if (!message) return;
    
    const type = prompt('Type (info/warning/error/success):', 'info');
    if (!type) return;
    
    const hours = prompt('Duration in hours:', '24');
    if (!hours) return;
    
    const startTime = new Date();
    const endTime = new Date(startTime.getTime() + parseInt(hours) * 60 * 60 * 1000);
    
    try {
        showLoading();
        const response = await fetch(`${API_BASE_URL}/api/admin/broadcasts`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${authToken}`
            },
            body: JSON.stringify({
                message,
                type,
                startTime,
                endTime,
                isActive: true
            })
        });
        
        const result = await response.json();
        hideLoading();
        
        if (result.status === 'success') {
            showAlert('Broadcast created successfully', 'success');
            loadAdminBroadcasts();
            loadBroadcasts(); // Refresh user view
        } else {
            showAlert(result.message || 'Failed to create broadcast', 'error');
        }
    } catch (error) {
        hideLoading();
        showAlert('Failed to create broadcast', 'error');
    }
}

async function editBroadcast(broadcastId) {
    const isActive = confirm('Make this broadcast active?');
    
    try {
        showLoading();
        const response = await fetch(`${API_BASE_URL}/api/admin/broadcasts/${broadcastId}`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${authToken}`
            },
            body: JSON.stringify({ isActive })
        });
        
        const result = await response.json();
        hideLoading();
        
        if (result.status === 'success') {
            showAlert('Broadcast updated successfully', 'success');
            loadAdminBroadcasts();
            loadBroadcasts();
        } else {
            showAlert(result.message || 'Failed to update broadcast', 'error');
        }
    } catch (error) {
        hideLoading();
        showAlert('Failed to update broadcast', 'error');
    }
}

async function deleteBroadcast(broadcastId) {
    if (confirm('Are you sure you want to delete this broadcast?')) {
        try {
            showLoading();
            const response = await fetch(`${API_BASE_URL}/api/admin/broadcasts/${broadcastId}`, {
                method: 'DELETE',
                headers: { 'Authorization': `Bearer ${authToken}` }
            });
            
            const result = await response.json();
            hideLoading();
            
            if (result.status === 'success') {
                showAlert('Broadcast deleted successfully', 'success');
                loadAdminBroadcasts();
                loadBroadcasts();
            } else {
                showAlert(result.message || 'Failed to delete broadcast', 'error');
            }
        } catch (error) {
            hideLoading();
            showAlert('Failed to delete broadcast', 'error');
        }
    }
}

// ==================== ADMIN CONFIG ====================
async function loadAdminConfig() {
    try {
        const response = await fetch(`${API_BASE_URL}/api/admin/config`, {
            headers: { 'Authorization': `Bearer ${authToken}` }
        });
        
        const result = await response.json();
        
        if (result.status === 'success') {
            document.getElementById('config-api-key').value = result.data.apiKey || '';
            document.getElementById('config-api-url').value = result.data.apiUrl || 'https://relay-wzlz.onrender.com';
        }
    } catch (error) {
        console.error('Failed to load config:', error);
    }
}

async function saveConfig(apiKey, apiUrl) {
    try {
        showLoading();
        const response = await fetch(`${API_BASE_URL}/api/admin/config`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${authToken}`
            },
            body: JSON.stringify({ apiKey, apiUrl })
        });
        
        const result = await response.json();
        hideLoading();
        
        if (result.status === 'success') {
            showAlert('Configuration saved successfully', 'success');
        } else {
            showAlert(result.message || 'Failed to save configuration', 'error');
        }
    } catch (error) {
        hideLoading();
        showAlert('Failed to save configuration', 'error');
    }
}

// ==================== ADMIN LOGS ====================
async function loadAdminLogs() {
    try {
        const response = await fetch(`${API_BASE_URL}/api/admin/logs`, {
            headers: { 'Authorization': `Bearer ${authToken}` }
        });
        
        const result = await response.json();
        
        if (result.status === 'success') {
            renderAdminLogs(result.data.logs);
        }
    } catch (error) {
        console.error('Failed to load logs:', error);
    }
}

function renderAdminLogs(logs) {
    const container = document.getElementById('logs-table');
    
    let html = `
        <table>
            <thead>
                <tr>
                    <th>Timestamp</th>
                    <th>User</th>
                    <th>Action</th>
                    <th>Command</th>
                    <th>Success</th>
                    <th>IP</th>
                </tr>
            </thead>
            <tbody>
    `;
    
    logs.forEach(log => {
        html += `
            <tr>
                <td>${new Date(log.timestamp).toLocaleString()}</td>
                <td>${log.username || '-'}</td>
                <td>${log.action}</td>
                <td>${log.commandType || '-'}</td>
                <td>
                    <span style="color: ${log.success ? 'var(--success)' : 'var(--error)'}">
                        ${log.success ? '✓' : '✗'}
                    </span>
                </td>
                <td>${log.ipAddress || '-'}</td>
            </tr>
        `;
    });
    
    html += '</tbody></table>';
    container.innerHTML = html;
}

// ==================== SETUP ADMIN ACTIONS ====================
function setupAdminActions() {
    // Config form
    document.getElementById('config-form').addEventListener('submit', (e) => {
        e.preventDefault();
        const apiKey = document.getElementById('config-api-key').value;
        const apiUrl = document.getElementById('config-api-url').value;
        saveConfig(apiKey, apiUrl);
    });
    
    // Add buttons
    document.getElementById('add-command-btn').addEventListener('click', addCommand);
    document.getElementById('add-plan-btn').addEventListener('click', addPlan);
    document.getElementById('add-broadcast-btn').addEventListener('click', addBroadcast);
}

// Export functions to global scope
window.editUserCredits = editUserCredits;
window.toggleUser = toggleUser;
window.addCommand = addCommand;
window.editCommand = editCommand;
window.deleteCommand = deleteCommand;
window.addPlan = addPlan;
window.editPlan = editPlan;
window.deletePlan = deletePlan;
window.addBroadcast = addBroadcast;
window.editBroadcast = editBroadcast;
window.deleteBroadcast = deleteBroadcast;
window.loadAdminDashboard = loadAdminDashboard;
