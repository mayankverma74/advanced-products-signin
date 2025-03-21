// Add this at the top of the file
const API_BASE_URL = 'https://advanced-products-backend.onrender.com';

// Check authentication status
async function isAuthenticated() {
    const token = localStorage.getItem('token');
    if (!token) return false;
    
    try {
        const response = await fetch(`${API_BASE_URL}/api/verify-token`, {
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });
        
        if (!response.ok) {
            localStorage.removeItem('token');
            localStorage.removeItem('user');
            return false;
        }
        
        return true;
    } catch (error) {
        console.error('Auth check failed:', error);
        localStorage.removeItem('token');
        localStorage.removeItem('user');
        return false;
    }
}

// Redirect to login if not authenticated
async function checkAuth() {
    if (!await isAuthenticated()) {
        window.location.href = '/login';
    }
}

// Redirect to dashboard if already authenticated
async function checkAlreadyAuth() {
    if (window.location.pathname === '/login' || window.location.pathname === '/login.html') {
        if (await isAuthenticated()) {
            window.location.href = '/dashboard';
        }
    }
}

// Get user data
function getUserData() {
    const user = localStorage.getItem('user');
    return user ? JSON.parse(user) : null;
}

// Logout function
function logout() {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    window.location.href = '/login';
}

// Add token to fetch requests
function getAuthHeaders() {
    const token = localStorage.getItem('token');
    return token ? { 'Authorization': `Bearer ${token}` } : {};
}

// Update all fetch calls to use API_BASE_URL
// For example:
async function login(phone, password) {
    try {
        const response = await fetch(`${API_BASE_URL}/api/login`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ phone, password })
        });
        // ... rest of the function
    } catch (error) {
        console.error('Login error:', error);
        throw error;
    }
}

// Update other functions similarly
