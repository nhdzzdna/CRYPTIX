/* static/js/crypto_tools.js — formulir Crypto Tools */

(function () {
  'use strict';

  function updateForm() {
    const c = document.getElementById('cipher-select').value;
    const a = document.getElementById('action-select').value;
    document.getElementById('key-field').style.display = c === 'super' ? 'none' : 'block';
    document.getElementById('passphrase-field').style.display = c === 'super' ? 'block' : 'none';
    document.getElementById('steps-field').style.display = (c === 'super' && a === 'encrypt') ? 'block' : 'none';
  }

  function copyResult() {
    const pre = document.querySelector('.output-box');
    if (pre && navigator.clipboard) {
      navigator.clipboard.writeText(pre.textContent);
    }
  }

  const cipherSelect = document.getElementById('cipher-select');
  const actionSelect = document.getElementById('action-select');
  const copyBtn = document.getElementById('copy-result-btn');

  if (!cipherSelect || !actionSelect) {
    return;
  }

  cipherSelect.addEventListener('change', updateForm);
  actionSelect.addEventListener('change', updateForm);
  if (copyBtn) {
    copyBtn.addEventListener('click', copyResult);
  }

  updateForm();
})();
