// Function to calculate final balance
function calculateBalance(rent, water, electricity, garbage, totalPaid) {
    const totalDue = parseFloat(rent) + parseFloat(water) + parseFloat(electricity) + parseFloat(garbage);
    const balance = totalDue - parseFloat(totalPaid);
    
    if (balance === 0) return { status: 'PAID', color: 'text-green-600' };
    if (balance < 0) return { status: 'CREDIT', color: 'text-blue-600' };
    return { status: 'ARREARS', color: 'text-red-600' };
}

// This logic will update the "Status" badges on your dashboard automatically
