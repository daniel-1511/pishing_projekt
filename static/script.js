// ================================
// Light-/Dark-Mode Toggle Switch und Hamburger-Menü
// ================================
document.addEventListener("DOMContentLoaded", function () {
    const toggle = document.querySelector("#darkModeToggle");
    const body = document.body;
    const menu = document.querySelector("#sideMenu");
    const menuIcon = document.querySelector(".menu-icon");

    // ================================
    // Dark / Light Mode beim Laden
    // ================================
    if (localStorage.getItem("darkmode") === "true") {
        body.classList.add("dark-mode");
        body.classList.remove("light-mode");
        if (toggle) toggle.checked = true;
    } else {
        body.classList.add("light-mode");
        body.classList.remove("dark-mode");
        if (toggle) toggle.checked = false;
    }

    // Toggle wechseln
    if (toggle) {
        toggle.addEventListener("change", function () {
            if (toggle.checked) {
                body.classList.add("dark-mode");
                body.classList.remove("light-mode");
                localStorage.setItem("darkmode", "true");
            } else {
                body.classList.add("light-mode");
                body.classList.remove("dark-mode");
                localStorage.setItem("darkmode", "false");
            }
        });
    }

    // ================================
    // Hamburger-Menü
    // ================================
    if (menuIcon && menu) {
        menuIcon.addEventListener("click", function () {
            menu.style.right = (menu.style.right === "0px") ? "-250px" : "0px";
        });
    }

    // ================================
    // 🤖 KI-CHAT (OLLAMA)
    // ================================
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

        // Ladeanzeige
        const loadingId = "loading-" + Date.now();
        chatBox.innerHTML += `
            <div class="chat-bot" id="${loadingId}">
                🤖 KI denkt nach...
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

    // ================================
    // Hilfsfunktionen
    // ================================
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