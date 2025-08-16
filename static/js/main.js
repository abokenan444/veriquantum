// main.js - Core frontend functionality for VeriQuantum

document.addEventListener("DOMContentLoaded", function () {
    console.log("Main JS loaded successfully ✅");

    // Example: Toggle dark mode
    const darkModeToggle = document.getElementById("darkModeToggle");
    if (darkModeToggle) {
        darkModeToggle.addEventListener("click", function () {
            document.body.classList.toggle("dark-mode");
        });
    }

    // Example: Form validation
    const forms = document.querySelectorAll("form");
    forms.forEach(form => {
        form.addEventListener("submit", function (e) {
            let valid = true;
            const inputs = form.querySelectorAll("input[required], textarea[required]");
            inputs.forEach(input => {
                if (!input.value.trim()) {
                    input.classList.add("error");
                    valid = false;
                } else {
                    input.classList.remove("error");
                }
            });

            if (!valid) {
                e.preventDefault();
                alert("⚠ Please fill in all required fields.");
            }
        });
    });

    // Example: Smooth scroll for anchor links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener("click", function (e) {
            e.preventDefault();
            document.querySelector(this.getAttribute("href")).scrollIntoView({
                behavior: "smooth"
            });
        });
    });
});
