/*
script.js — SkyPass Guard Frontend Logic (FIXED)

This JavaScript file handles:
- Tab navigation with slide animation
- Real-time password strength checking
- Animated circular score ring
- Password generation
- Encryption/decryption
- History table display
- CSV export
- Copy-to-clipboard functions
*/

// ============================================================
// NAVIGATION TABS WITH SLIDE ANIMATION
// ============================================================

document.querySelectorAll('.nav-btn').forEach(btn => {
    btn.addEventListener('click', function() {
        const sectionId = this.getAttribute('data-section');
        showSection(sectionId);
    });
});


function showSection(sectionId) {
    // Remove active class from all nav buttons
    document.querySelectorAll('.nav-btn').forEach(btn => {
        btn.classList.remove('active');
    });
    
    // Add active class to clicked button
    document.querySelector(`.nav-btn[data-section="${sectionId}"]`).classList.add('active');
    
    // Remove active class from all sections
    document.querySelectorAll('.section').forEach(section => {
        section.classList.remove('active');
    });
    
    // Add active class to target section (with slide animation)
    document.getElementById(sectionId).classList.add('active');
}


// ============================================================
// PASSWORD STRENGTH CHECKER
// ============================================================

document.getElementById('passwordInput').addEventListener('input', function() {
    const password = this.value;
    checkPasswordStrength(password);
});


async function checkPasswordStrength(password) {
    try {
        const response = await fetch('/api/check-password', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ password: password })
        });
        
        const result = await response.json();
        updateStrengthUI(result);
        
    } catch (error) {
        console.error('Error checking password strength:', error);
    }
}


function updateStrengthUI(result) {
    updateScoreRing(result.score, result.color);
    document.getElementById('scoreNumber').textContent = result.score;
    
    const strengthLabel = document.getElementById('strengthLabel');
    strengthLabel.textContent = result.label;
    strengthLabel.style.color = result.color;
    
    // Update progress bar
    const progressBar = document.getElementById('progressBar');
    progressBar.style.width = result.score + '%';
    progressBar.style.background = result.color;
    
    // Update issues
    const issuesSection = document.getElementById('issuesSection');
    const issuesList = document.getElementById('issuesList');
    
    if (result.issues && result.issues.length > 0) {
        issuesSection.style.display = 'block';
        issuesList.innerHTML = '';
        
        result.issues.forEach(issue => {
            const li = document.createElement('li');
            li.textContent = issue;
            issuesList.appendChild(li);
        });
    } else {
        issuesSection.style.display = 'none';
    }
    
    // Update suggestions
    const suggestionsSection = document.getElementById('suggestionsSection');
    const suggestionsList = document.getElementById('suggestionsList');
    
    if (result.suggestions && result.suggestions.length > 0) {
        suggestionsSection.style.display = 'block';
        suggestionsList.innerHTML = '';
        
        result.suggestions.forEach(suggestion => {
            const li = document.createElement('li');
            li.textContent = suggestion;
            suggestionsList.appendChild(li);
        });
    } else {
        suggestionsSection.style.display = 'none';
    }
    
    // Update info
    const infoSection = document.getElementById('infoSection');
    
    if (result.entropy > 0) {
        infoSection.style.display = 'block';
        document.getElementById('entropyValue').textContent = result.entropy.toFixed(1);
        document.getElementById('crackTimeValue').textContent = result.crack_time;
    } else {
        infoSection.style.display = 'none';
    }
}


function updateScoreRing(score, color) {
    const progressCircle = document.querySelector('.ring-progress');
    const circumference = 314;
    const progress = (score / 100) * circumference;
    
    progressCircle.style.strokeDasharray = `${progress} ${circumference - progress}`;
    progressCircle.style.stroke = color;
}


// ============================================================
// PASSWORD GENERATOR
// ============================================================

document.getElementById('generateBtn').addEventListener('click', function() {
    const lengthSelect = document.getElementById('lengthSelect');
    const symbolsCheck = document.getElementById('symbolsCheck');
    
    const length = parseInt(lengthSelect.value, 10);
    const useSymbols = symbolsCheck.checked;
    
    generatePassword(length, useSymbols);
});


async function generatePassword(length, useSymbols) {
    try {
        const response = await fetch('/api/generate-password', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ 
                length: length, 
                use_symbols: useSymbols 
            })
        });
        
        if (!response.ok) {
            console.error('Server error:', response.status);
            alert('Password generation failed. Please try again.');
            return;
        }
        
        const result = await response.json();
        
        if (result.error) {
            console.error('API error:', result.error);
            alert('Password generation failed: ' + result.error);
            return;
        }
        
        const generatedContainer = document.getElementById('generatedContainer');
        const generatedPassword = document.getElementById('generatedPassword');
        
        generatedPassword.value = result.password;
        generatedContainer.style.display = 'flex';
        
    } catch (error) {
        console.error('Error generating password:', error);
        alert('Password generation failed. Check your console for details.');
    }
}


document.getElementById('copyBtn').addEventListener('click', function() {
    const password = document.getElementById('generatedPassword').value;
    copyToClipboard(password, 'copyBtn');
});


// ============================================================
// ENCRYPTION / DECRYPTION
// ============================================================

document.getElementById('encryptBtn').addEventListener('click', function() {
    const password = document.getElementById('cryptoInput').value;
    
    if (password) {
        encryptPassword(password);
    } else {
        alert('Please enter a password to encrypt');
    }
});


document.getElementById('decryptBtn').addEventListener('click', function() {
    const encryptedPassword = document.getElementById('cryptoInput').value;
    
    if (encryptedPassword) {
        decryptPassword(encryptedPassword);
    } else {
        alert('Please enter an encrypted password to decrypt');
    }
});


async function encryptPassword(password) {
    try {
        const response = await fetch('/api/encrypt-password', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ password: password })
        });
        
        const result = await response.json();
        
        if (result.error) {
            alert('Encryption failed: ' + result.error);
            return;
        }
        
        displayCryptoResult(result.encrypted, 'encrypted');
        
    } catch (error) {
        console.error('Error encrypting password:', error);
        alert('Encryption failed. Please try again.');
    }
}


async function decryptPassword(encryptedPassword) {
    try {
        const response = await fetch('/api/decrypt-password', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ encrypted_password: encryptedPassword })
        });
        
        const result = await response.json();
        
        if (result.error) {
            alert('Decryption failed: ' + result.error);
            return;
        }
        
        displayCryptoResult(result.decrypted, 'decrypted');
        
    } catch (error) {
        console.error('Error decrypting password:', error);
        alert('Decryption failed. Please try again.');
    }
}


function displayCryptoResult(result, type) {
    const cryptoResultContainer = document.getElementById('cryptoResultContainer');
    const cryptoResult = document.getElementById('cryptoResult');
    
    cryptoResult.value = result;
    cryptoResultContainer.style.display = 'block';
    
    const resultLabel = document.querySelector('.result-label');
    resultLabel.textContent = type === 'encrypted' ? 'Encrypted Result:' : 'Decrypted Result:';
}


document.getElementById('copyCryptoBtn').addEventListener('click', function() {
    const result = document.getElementById('cryptoResult').value;
    copyToClipboard(result, 'copyCryptoBtn');
});


// ============================================================
// HISTORY TABLE
// ============================================================

document.addEventListener('DOMContentLoaded', function() {
    loadHistory();
});


async function loadHistory() {
    try {
        const response = await fetch('/api/history');
        const checks = await response.json();
        displayHistory(checks);
        
    } catch (error) {
        console.error('Error loading history:', error);
    }
}


function displayHistory(checks) {
    const historyTableBody = document.getElementById('historyTableBody');
    const noHistoryMessage = document.getElementById('noHistoryMessage');
    
    if (checks.length === 0) {
        historyTableBody.innerHTML = '';
        noHistoryMessage.style.display = 'block';
    } else {
        noHistoryMessage.style.display = 'none';
        historyTableBody.innerHTML = '';
        
        checks.forEach(check => {
            const row = document.createElement('tr');
            
            const timestamp = new Date(check.created_at).toLocaleString();
            
            row.innerHTML = `
                <td>${timestamp}</td>
                <td><strong>${check.score}</strong></td>
                <td style="color: ${getStrengthColor(check.score)}">${check.label}</td>
                <td>${check.issues}</td>
                <td>${check.suggestions}</td>
            `;
            
            historyTableBody.appendChild(row);
        });
    }
}


function getStrengthColor(score) {
    if (score < 30) return '#ef4444';
    if (score < 50) return '#f59e0b';
    if (score < 70) return '#3b82f6';
    if (score < 90) return '#10b981';
    return '#059669';
}


// ============================================================
// CSV EXPORT
// ============================================================

document.getElementById('exportBtn').addEventListener('click', function() {
    exportToCSV();
});


async function exportToCSV() {
    try {
        const response = await fetch('/api/export-csv');
        const result = await response.json();
        
        alert(`CSV exported successfully: ${result.filename}`);
        
    } catch (error) {
        console.error('Error exporting to CSV:', error);
        alert('Export failed. Please try again.');
    }
}


// ============================================================
// COPY TO CLIPBOARD
// ============================================================

function copyToClipboard(text, buttonId) {
    navigator.clipboard.writeText(text).then(() => {
        const button = document.getElementById(buttonId);
        const originalText = button.innerHTML;
        button.innerHTML = '<span class="btn-icon">✓</span><span class="btn-text">Copied!</span>';
        
        setTimeout(() => {
            button.innerHTML = originalText;
        }, 2000);
        
    }).catch(error => {
        console.error('Error copying to clipboard:', error);
        alert('Failed to copy. Please try again.');
    });
}