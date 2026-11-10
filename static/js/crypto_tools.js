/* static/js/crypto_tools.js — formulir Crypto Tools */

(function () {
  'use strict';

  function updateForm() {
    const c = document.getElementById('cipher-select').value;
    const a = document.getElementById('action-select').value;
    document.getElementById('key-field').style.display = c === 'super' ? 'none' : 'block';
    document.getElementById('passphrase-field').style.display = c === 'super' ? 'block' : 'none';
    document.getElementById('steps-field').style.display = (c === 'super' && a === 'encrypt') ? 'block' : 'none';
    syncTabs(c);
  }

  function syncTabs(value) {
    tabs.forEach(function (tab) {
      const active = tab.dataset.cipher === value;
      tab.classList.toggle('is-active', active);
      tab.setAttribute('aria-selected', active ? 'true' : 'false');
      tab.setAttribute('tabindex', active ? '0' : '-1');
    });
  }

  function selectCipher(value) {
    cipherSelect.value = value;
    cipherSelect.dispatchEvent(new Event('change', { bubbles: true }));
  }

  function copyResult() {
    const pre = document.querySelector('.output-box');
    if (pre && navigator.clipboard) {
      navigator.clipboard.writeText(pre.textContent);
      if (copyBtn) {
        const original = copyBtn.innerHTML;
        copyBtn.textContent = 'Tersalin';
        window.setTimeout(function () { copyBtn.innerHTML = original; }, 1500);
      }
    }
  }

  function setLoading(form) {
    const btn = document.getElementById('crypto-submit-btn');
    if (!btn) { return; }
    btn.disabled = true;
    btn.classList.add('is-loading');
    const label = btn.querySelector('.crypto-submit-label');
    if (label) { label.textContent = 'Memproses…'; }
  }

  const form = document.getElementById('crypto-form');
  const cipherSelect = document.getElementById('cipher-select');
  const actionSelect = document.getElementById('action-select');
  const copyBtn = document.getElementById('copy-result-btn');
  const tabs = Array.prototype.slice.call(document.querySelectorAll('.crypto-tab'));

  if (!cipherSelect || !actionSelect) {
    return;
  }

  if (form && tabs.length) {
    form.classList.add('crypto-enhanced');

    tabs.forEach(function (tab) {
      tab.addEventListener('click', function () {
        selectCipher(tab.dataset.cipher);
      });
    });

    const tablist = document.querySelector('.crypto-tabs');
    if (tablist) {
      tablist.addEventListener('keydown', function (event) {
        const index = tabs.indexOf(document.activeElement);
        if (index === -1) { return; }
        let next = null;
        if (event.key === 'ArrowRight') { next = tabs[(index + 1) % tabs.length]; }
        if (event.key === 'ArrowLeft') { next = tabs[(index - 1 + tabs.length) % tabs.length]; }
        if (next) {
          event.preventDefault();
          next.focus();
          selectCipher(next.dataset.cipher);
        }
      });
    }
  }

  cipherSelect.addEventListener('change', updateForm);
  actionSelect.addEventListener('change', updateForm);
  if (copyBtn) {
    copyBtn.addEventListener('click', copyResult);
  }
  if (form) {
    form.addEventListener('submit', function () { setLoading(form); });
  }

  updateForm();
})();
