// content.js — Injected into every page
// Monitors form submissions with password fields

(function () {
  'use strict';

  document.addEventListener('submit', event => {
    const form = event.target;
    if (!form.querySelector('input[type="password"]')) return;
    chrome.runtime.sendMessage({
      action: 'passwordFormSubmitted',
      url: window.location.href
    });
  });
})();
