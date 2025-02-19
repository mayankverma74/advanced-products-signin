// Check authentication status
function isAuthenticated() {
    const token = localStorage.getItem('token');
    const user = localStorage.getItem('user');
    return token && user;
}

// Redirect to login if not authenticated
function checkAuth() {
    if (!isAuthenticated()) {
        window.location.href = '/login.html';
    }
}

// Redirect to dashboard if already authenticated
function checkAlreadyAuth() {
    if (isAuthenticated()) {
        window.location.href = '/dashboard.html';
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
    window.location.href = '/login.html';
}
