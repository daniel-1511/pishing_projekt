// Light-/Dark-Mode Toggle Switch und Hamburger-Menü
document.addEventListener("DOMContentLoaded", function () {
    const toggle = document.querySelector("#darkModeToggle");
    const body = document.body;
    const menu = document.querySelector("#sideMenu"); // Hamburger-Menü
    const menuIcon = document.querySelector(".menu-icon");

    // Beim Laden den aktuellen Modus anhand von LocalStorage setzen
    if (localStorage.getItem("darkmode") === "true") {
        body.classList.add("dark-mode");
        body.classList.remove("light-mode");
        toggle.checked = true; // Toggle auf "checked" setzen
    } else {
        body.classList.add("light-mode");
        body.classList.remove("dark-mode");
        toggle.checked = false; // Toggle auf "unchecked" setzen
    }

    // Event Listener für den Toggle-Button (Dark/Light Mode)
    toggle.addEventListener("change", function () {
        if (toggle.checked) {
            body.classList.remove("light-mode");
            body.classList.add("dark-mode");
            localStorage.setItem("darkmode", "true"); // Modus speichern
        } else {
            body.classList.remove("dark-mode");
            body.classList.add("light-mode");
            localStorage.setItem("darkmode", "false"); // Modus speichern
        }
    });

    // Event Listener für das Hamburger-Menü
    menuIcon.addEventListener("click", function () {
        // Menü ein-/ausblenden
        if (menu.style.right === "0px") {
            menu.style.right = "-250px"; // Menü schließen
        } else {
            menu.style.right = "0px"; // Menü öffnen
        }
    });
});