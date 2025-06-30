// shared/dateUtils.js
function calculateDaysRemaining(dueDate, currentDate = new Date()) {
    if (!dueDate) return 0;
    
    const due = new Date(dueDate);
    const now = new Date(currentDate);
    
    // Calculate difference in milliseconds
    const diffMs = due - now;
    
    // Convert to days and round down
    const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));
    
    return diffDays; // Negative means overdue
}

module.exports = { calculateDaysRemaining };