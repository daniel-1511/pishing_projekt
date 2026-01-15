// Hamburger-Menü und Dark/Light Mode Toggle
document.addEventListener("DOMContentLoaded", function () {
    const themeToggle = document.querySelector("#themeToggle");
    const body = document.body;
    const menu = document.querySelector("#sideMenu");
    const menuIcon = document.querySelector(".menu-icon");

    // Dark/Light Mode beim Laden
    if (localStorage.getItem("darkmode") === "true") {
        body.classList.add("dark-mode");
        if (themeToggle) themeToggle.checked = true;
    } else {
        body.classList.remove("dark-mode");
        if (themeToggle) themeToggle.checked = false;
    }

    // Theme Toggle Event
    if (themeToggle) {
        themeToggle.addEventListener("change", function () {
            body.classList.toggle("dark-mode");
            const isDark = body.classList.contains("dark-mode");
            localStorage.setItem("darkmode", isDark ? "true" : "false");
        });
    }

    if (menuIcon && menu) {
        menuIcon.addEventListener("click", function () {
            menu.style.right = (menu.style.right === "0px") ? "-250px" : "0px";
        });
    }

    // 🤖 KI-CHAT (OLLAMA)
    const chatForm = document.querySelector("#chatForm");
    const chatInput = document.querySelector("#chatInput");
    const chatBox = document.querySelector("#chatBox");

    if (!chatForm || !chatInput || !chatBox) return;

    chatForm.addEventListener("submit", async function (e) {
        e.preventDefault();

        const message = chatInput.value.trim();
        if (!message) return;

        // User Message anzeigen
        chatBox.innerHTML += `
            <div class="chat-user">
                👤 ${escapeHtml(message)}
            </div>
        `;
        chatInput.value = "";
        chatBox.scrollTop = chatBox.scrollHeight;

        // Animierte Ladeanzeige
        const loadingId = "loading-" + Date.now();
        chatBox.innerHTML += `
            <div class="chat-bot" id="${loadingId}">
                🤖 <span class="loading-spinner"></span><span class="loading-text">Die KI denkt nach...</span>
            </div>
        `;
        chatBox.scrollTop = chatBox.scrollHeight;

        try {
            const formData = new FormData();
            formData.append("message", message);

            const response = await fetch("/chat", {
                method: "POST",
                body: formData
            });

            const data = await response.json();
            const answer = data.answer || "Keine Antwort erhalten.";

            // Ladeanzeige ersetzen
            const loadingEl = document.getElementById(loadingId);
            if (loadingEl) {
                loadingEl.innerHTML = `
                    🤖 ${formatAnswer(answer)}
                `;
            }
        } catch (error) {
            const loadingEl = document.getElementById(loadingId);
            if (loadingEl) {
                loadingEl.innerHTML =
                    `<span style="color:red;">🤖 Fehler bei der KI-Verarbeitung</span>`;
            }
        }

        chatBox.scrollTop = chatBox.scrollHeight;
    });

    // Hilfsfunktionen
    function escapeHtml(text) {
        return text
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;");
    }

    function formatAnswer(text) {
        return escapeHtml(text).replace(/\n/g, "<br>");
    }
});