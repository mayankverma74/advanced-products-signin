// Add API base URL
const API_BASE_URL = 'https://advanced-products-backend.onrender.com';

// Update all fetch calls to use API_BASE_URL
async function loadUsers() {
    try {
        const response = await fetch(`${API_BASE_URL}/api/admin/users`, {
            headers: {
                'Authorization': `Bearer ${localStorage.getItem('token')}`
            }
        });
        // ... rest of the function
    } catch (error) {
        console.error('Error loading users:', error);
        showError('Failed to load users');
    }
}

async function loadTransactions() {
    try {
        const response = await fetch(`${API_BASE_URL}/api/admin/transactions`, {
            headers: {
                'Authorization': `Bearer ${localStorage.getItem('token')}`
            }
        });
        // ... rest of the function
    } catch (error) {
        console.error('Error loading transactions:', error);
        showError('Failed to load transactions');
    }
}

async function loadStats() {
    try {
        const response = await fetch(`${API_BASE_URL}/api/admin/stats`, {
            headers: {
                'Authorization': `Bearer ${localStorage.getItem('token')}`
            }
        });
        // ... rest of the function
    } catch (error) {
        console.error('Error loading stats:', error);
        showError('Failed to load statistics');
    }
} 