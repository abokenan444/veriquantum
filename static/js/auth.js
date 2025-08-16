// auth.js - handle login/register forms without full page reload (optional)
document.addEventListener("DOMContentLoaded", () => {
  const loginForm = document.querySelector('form[data-vq="login"]');
  if (loginForm) {
    loginForm.addEventListener("submit", async (e) => {
      // normal form submit (server handles redirect) if JS fails
      if (loginForm.dataset.ajax !== "1") return;
      e.preventDefault();
      try {
        const data = vqSerializeForm(loginForm);
        const res = await VQ_API.post("/login", data);
        vqToast.ok("Welcome!");
        // Backend could return {"next": "/dashboard"} if you add JSON branch
        window.location.href = (res && res.next) || "/dashboard";
      } catch (err) {
        vqToast.error(err.message || "Login failed");
      }
    });
  }

  const registerForm = document.querySelector('form[data-vq="register"]');
  if (registerForm) {
    registerForm.addEventListener("submit", async (e) => {
      if (registerForm.dataset.ajax !== "1") return;
      e.preventDefault();
      try {
        const data = vqSerializeForm(registerForm);
        await VQ_API.post("/register", data);
        vqToast.ok("Account created. Please sign in.");
        window.location.href = "/login";
      } catch (err) {
        vqToast.error(err.message || "Registration failed");
      }
    });
  }

  // forgot/reset placeholders (when endpoints are added)
  const forgotForm = document.querySelector('form[data-vq="forgot"]');
  if (forgotForm) {
    forgotForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      try {
        const data = vqSerializeForm(forgotForm);
        await VQ_API.post("/auth/forgot", data);
        vqToast.ok("If the email exists, a reset link was sent.");
      } catch (err) {
        vqToast.error(err.message || "Error sending reset email");
      }
    });
  }

  const resetForm = document.querySelector('form[data-vq="reset"]');
  if (resetForm) {
    resetForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      try {
        const data = vqSerializeForm(resetForm);
        await VQ_API.post("/auth/reset", data);
        vqToast.ok("Password updated. You can login now.");
        window.location.href = "/login";
      } catch (err) {
        vqToast.error(err.message || "Reset failed");
      }
    });
  }
});
