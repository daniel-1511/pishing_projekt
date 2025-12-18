//Light Dark Mode Toggle Switch
document.addEventListener("DOMContentLoaded", function () {
    const toggle = document.querySelector("#darkModeToggle");
    const body = document.body;

    // Beim Laden den aktuellen Modus anhand von LocalStorage setzen
    if (localStorage.getItem("darkmode") === "true") {
        body.classList.add("dark");
        toggle.checked = true; // Toggle auf "checked" setzen
    }

    // Event Listener für den Toggle-Button
    toggle.addEventListener("change", function () {
        body.classList.toggle("dark"); // Schaltet den Modus
        localStorage.setItem("darkmode", body.classList.contains("dark")); // Modus speichern
    });
});