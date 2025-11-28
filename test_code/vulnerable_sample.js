// This file contains intentional vulnerabilities for testing the Security Agent.

const express = require('express');
const app = express();
const fs = require('fs');
const crypto = require('crypto');
const mysql = require('mysql');


function hashPassword(password) {
    // MD5 is broken and should not be used
    return crypto.createHash('md5').update(password).digest('hex');
}

app.get('/execute', (req, res) => {
    const userCode = req.query.code;
    // Dangerous: evaluating user input
    eval(userCode); 
    res.send("Executed");
});


function updateProfile(userInput) {
    const profileDiv = document.getElementById('profile');
    // Dangerous: direct assignment to innerHTML without sanitization
    profileDiv.innerHTML = userInput;
}


app.get('/user', (req, res) => {
    const userId = req.query.id;
    const connection = mysql.createConnection({/*...*/});
    
    // Dangerous: String concatenation in SQL
    const query = "SELECT * FROM users WHERE id = " + userId;
    
    connection.query(query, (err, results) => {
        if (err) throw err;
        res.json(results);
    });
});


app.get('/file', (req, res) => {
    const filename = req.query.name;
    // Dangerous: reading file based on user input with no validation
    fs.readFile(filename, 'utf8', (err, data) => {
        res.send(data);
    });
});


function safeUpdate(userInput) {
    const div = document.getElementById('output');
    // TextContent is safe from XSS
    div.textContent = userInput;
}