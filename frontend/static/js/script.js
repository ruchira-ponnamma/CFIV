(() => {
    const menuButton = document.querySelector(".menu-toggle");
    const sidebar = document.querySelector("#primary-sidebar");
    const backdrop = document.querySelector(".sidebar-backdrop");
    const mobileLayout = window.matchMedia("(max-width: 820px)");

    if (!menuButton || !sidebar || !backdrop) {
        return;
    }

    function setMenuOpen(isOpen, returnFocus = false) {
        document.body.classList.toggle("sidebar-open", isOpen);
        menuButton.setAttribute("aria-expanded", String(isOpen));
        menuButton.setAttribute(
            "aria-label",
            isOpen ? "Close navigation menu" : "Open navigation menu"
        );
        sidebar.setAttribute("aria-hidden", String(mobileLayout.matches && !isOpen));
        sidebar.inert = mobileLayout.matches && !isOpen;

        if (returnFocus) {
            menuButton.focus();
        }
    }

    menuButton.addEventListener("click", () => {
        const isOpen = menuButton.getAttribute("aria-expanded") === "true";
        setMenuOpen(!isOpen);
    });

    backdrop.addEventListener("click", () => setMenuOpen(false));

    document.addEventListener("keydown", (event) => {
        if (event.key === "Escape" && menuButton.getAttribute("aria-expanded") === "true") {
            setMenuOpen(false, true);
        }
    });

    sidebar.addEventListener("click", (event) => {
        if (event.target.closest("a")) {
            setMenuOpen(false);
        }
    });

    mobileLayout.addEventListener("change", () => setMenuOpen(false));
    setMenuOpen(false);
})();
