// dashboard.js - interactions for dashboard & sector pages
document.addEventListener("DOMContentLoaded", () => {
  const grid = document.querySelector('[data-vq="sectors-grid"]');
  if (grid) {
    grid.querySelectorAll("a[data-sector]").forEach(a => {
      a.addEventListener("mouseenter", () => a.classList.add("hover"));
      a.addEventListener("mouseleave", () => a.classList.remove("hover"));
    });
  }

  // Example: live health ping
  const healthEl = document.getElementById("healthIndicator");
  if (healthEl) {
    const ping = async () => {
      try {
        await VQ_API.get("/health");
        healthEl.textContent = "Online";
        healthEl.style.color = "#2e7d32";
      } catch {
        healthEl.textContent = "Offline";
        healthEl.style.color = "#d32f2f";
      }
    };
    ping();
    setInterval(ping, 8000);
  }
});
