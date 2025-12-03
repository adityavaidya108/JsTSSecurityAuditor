// API Handler with multiple security issues
const express = require('express');
const mysql = require('mysql2');
const fs = require('fs');
const http = require('http');

const app = express();
app.use(express.json());

// SQL Injection vulnerability - user input directly in query
app.post('/login', (req, res) => {
    const username = req.body.username;
    const password = req.body.password;
    
    const connection = mysql.createConnection({
        host: 'localhost',
        user: 'root',
        password: 'secret'
    });
    
    // Dangerous: String concatenation in SQL
    const query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
    connection.query(query, (err, results) => {
        if (err) {
            res.status(500).json({ error: err.message });
            return;
        }
        res.json(results);
    });
});

// Path Traversal vulnerability
app.get('/download', (req, res) => {
    const filePath = req.query.file;
    // Dangerous: No validation on user input
    fs.readFile(filePath, 'utf8', (err, data) => {
        if (err) {
            res.status(404).send('File not found');
            return;
        }
        res.send(data);
    });
});

// Insecure API call
app.get('/fetchData', (req, res) => {
    const url = req.query.url;
    // Dangerous: Using HTTP instead of HTTPS
    http.get(`http://${url}/api/data`, (response) => {
        let data = '';
        response.on('data', (chunk) => {
            data += chunk;
        });
        response.on('end', () => {
            res.json(JSON.parse(data));
        });
    });
});

// Safe usage - should be false positive
app.get('/safeQuery', (req, res) => {
    const connection = mysql.createConnection({/*...*/});
    // Safe: Using parameterized query
    const query = "SELECT * FROM users WHERE id = ?";
    connection.query(query, [req.query.id], (err, results) => {
        res.json(results);
    });
});

module.exports = app;

