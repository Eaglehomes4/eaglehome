// Function to calculate final balance
function calculateBalance(rent, water, electricity, garbage, totalPaid) {
    const totalDue = parseFloat(rent) + parseFloat(water) + parseFloat(electricity) + parseFloat(garbage);
    const balance = totalDue - parseFloat(totalPaid);
    
    if (Math.abs(balance) < 0.01) return { status: 'PAID', color: 'text-green-600', balance: 0 };
    if (balance < 0) return { status: 'CREDIT', color: 'text-blue-600', balance: Math.abs(balance) };
    return { status: 'ARREARS', color: 'text-red-600', balance: balance };
}

// Update dashboard status badges
function updateDashboardStatus() {
    // This would be called when the dashboard loads
    // In a real app, you would fetch data from the server
    console.log('Dashboard status update logic would go here');
}

// Format currency
function formatCurrency(amount) {
    return new Intl.NumberFormat('en-KE', {
        style: 'currency',
        currency: 'KES'
    }).format(amount);
}
