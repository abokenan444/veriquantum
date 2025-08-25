// api.js - Minimal fetch wrapper for VeriQuantum
const VQ_API = (function () {
  const defaultHeaders = { "Accept": "application/json" };

  async function request(path, { method = "GET", data = null, headers = {} } = {}) {
    const opts = { method, headers: { ...defaultHeaders, ...headers }, credentials: "same-origin" };
    if (data && !(data instanceof FormData)) {
      opts.headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(data);
    } else if (data instanceof FormData) {
      opts.body = data; // browser sets boundary
    }

    const res = await fetch(path, opts);
    const contentType = res.headers.get("content-type") || "";
    let payload = null;
    if (contentType.includes("application/json")) {
      payload = await res.json().catch(() => ({}));
    } else {
      payload = await res.text();
    }

    if (!res.ok) {
      const message = (payload && payload.message) || res.statusText || "Request failed";
      throw new Error(message);
    }
    return payload;
  }

  return {
    get: (path) => request(path, { method: "GET" }),
    post: (path, data) => request(path, { method: "POST", data }),
    put: (path, data) => request(path, { method: "PUT", data }),
    del: (path) => request(path, { method: "DELETE" }),
  };
})();
window.VQ_API = VQ_API;
