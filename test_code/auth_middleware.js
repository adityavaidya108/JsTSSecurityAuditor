// Authentication middleware with security issues
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// Weak cryptography - MD5 usage
function hashPassword(password) {
    // Dangerous: MD5 is cryptographically broken
    return crypto.createHash('md5').update(password).digest('hex');
}

// Weak random number generation
function generateSessionToken() {
    // Dangerous: Math.random() is not cryptographically secure
    return Math.random().toString(36).substring(2, 15);
}

// Authentication check - potential issue
function authenticateRequest(req, res, next) {
    // Potential issue: Direct access to authorization header without proper validation
    const token = req.headers['authorization'];
    
    if (!token) {
        return res.status(401).json({ error: 'No token provided' });
    }
    
    try {
        // This might be okay, but the pattern matches
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        res.status(401).json({ error: 'Invalid token' });
    }
}

// Prototype pollution vulnerability
function mergeUserData(userInput, defaultData) {
    // Dangerous: Object.assign can lead to prototype pollution
    return Object.assign({}, defaultData, userInput);
}

// Safe usage - should be false positive
function safeHashPassword(password) {
    // Safe: Using bcrypt or proper hashing
    return crypto.createHash('sha256').update(password).digest('hex');
}

module.exports = {
    hashPassword,
    generateSessionToken,
    authenticateRequest,
    mergeUserData,
    safeHashPassword
};

