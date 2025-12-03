// Data processing with mixed vulnerabilities
const express = require('express');
const fs = require('fs');
const path = require('path');

const app = express();

// Complex scenario: SQL injection with template literals
app.post('/search', (req, res) => {
    const searchTerm = req.body.term;
    const table = req.body.table;
    
    // Dangerous: Template literal in SQL query
    const query = `SELECT * FROM ${table} WHERE name LIKE '%${searchTerm}%'`;
    
    // Simulated database call
    console.log('Executing:', query);
    res.json({ message: 'Search completed' });
});

// Path traversal with path.join (might be safe if done correctly, but pattern matches)
app.get('/readConfig', (req, res) => {
    const configName = req.query.config;
    // Potentially dangerous: path.join with user input
    const configPath = path.join(__dirname, 'configs', configName);
    
    fs.readFile(configPath, 'utf8', (err, data) => {
        if (err) {
            res.status(500).send('Error reading config');
            return;
        }
        res.json(JSON.parse(data));
    });
});

// Prototype pollution
function processUserInput(userData) {
    const defaults = { role: 'user', permissions: [] };
    
    // Dangerous: Direct assignment to __proto__
    if (userData.__proto__) {
        Object.assign(defaults, userData);
    }
    
    return defaults;
}

// Code injection with new Function
function createDynamicFunction(functionBody) {
    // Dangerous: new Function with user input
    return new Function('return ' + functionBody)();
}

// Weak crypto - SHA1
function createChecksum(data) {
    const crypto = require('crypto');
    // Dangerous: SHA1 is weak
    return crypto.createHash('sha1').update(data).digest('hex');
}

// Safe usage - should be false positive
function safePathJoin(filename) {
    // Safe: Validating and sanitizing input
    if (filename.includes('..') || filename.includes('/')) {
        throw new Error('Invalid filename');
    }
    return path.join(__dirname, 'safe', filename);
}

module.exports = app;

