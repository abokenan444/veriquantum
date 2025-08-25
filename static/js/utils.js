// utils.js - common helpers (toast, debounce, serialize)
(function () {
  function debounce(fn, wait = 300) {
    let t;
    return (...args) => {
      clearTimeout(t);
      t = setTimeout(() => fn.apply(null, args), wait);
    };
  }

  function serializeForm(form) {
    const data = {};
    new FormData(form).forEach((v, k) => (data[k] = v));
    return data;
  }

  // tiny toast
  function toast(type, msg) {
    const el = document.createElement("div");
    el.textContent = msg;
    el.style.cssText = `
      position: fixed; right: 16px; bottom: 16px; padding: 10px 14px;
      border-radius: 6px; color: #fff; z-index: 9999; font: 14px/1.3 system-ui;
      background: ${type === "error" ? "#d32f2f" : type === "warn" ? "#ed6c02" : "#2e7d32"};
      box-shadow: 0 6px 18px rgba(0,0,0,.15);
    `;
    document.body.appendChild(el);
    setTimeout(() => el.remove(), 2800);
  }

  window.vqToast = {
    ok: (m) => toast("ok", m),
    warn: (m) => toast("warn", m),
    error: (m) => toast("error", m),
  };
  window.vqDebounce = debounce;
  window.vqSerializeForm = serializeForm;
})();
