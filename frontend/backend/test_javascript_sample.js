// Sample JavaScript file with AI hallucinations for testing
// This file should trigger multiple findings

const SECRET_API_KEY = "sk-1234567890abcdef"; // Hardcoded secret

function processUserInput(userInput) {
    // XSS vulnerability - using innerHTML
    document.getElementById('output').innerHTML = userInput;
}

function calculate() {
    // Magic number
    let result = 3.14159 * 5;
    return result;
}

function riskyOperation() {
    // Dangerous eval usage
    let code = "alert('Hacked!')";
    eval(code);
}

function executeCommand(cmd) {
    // Command injection risk
    const child_process = require('child_process');
    child_process.exec(cmd);
}

function emptyCatch() {
    try {
        JSON.parse('invalid json');
    } catch (e) {
        // Empty catch block - silently ignores errors
    }
}

function bareExcept() {
    try {
        someUndefinedFunction();
    } except: {
        // Bare except catches everything
    }
}

function nestedLoops() {
    // Nested loops - performance risk
    for (let i = 0; i < 100; i++) {
        for (let j = 0; j < 100; j++) {
            for (let k = 0; k < 100; k++) {
                console.log(i, j, k);
            }
        }
    }
}

// Console.log in production (should be flagged)
console.log("Debug information:", SECRET_API_KEY);

// Loose equality (should be flagged)
if (userInput == "admin") {
    // Allow admin access
}

var oldVariable = "using var instead of let/const"; // var usage
