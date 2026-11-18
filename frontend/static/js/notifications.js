(() => {
    const notifications = document.querySelectorAll("[data-notification]");

    notifications.forEach((notification) => {
        const closeButton = notification.querySelector("[data-notification-close]");
        const duration = Number(notification.dataset.dismissMs) || 8000;
        const notificationId = notification.dataset.notificationId;
        const fallback = notificationId
            ? Array.from(document.querySelectorAll("[data-notification-fallback]"))
                .find((element) => element.dataset.notificationId === notificationId)
            : null;
        let timeoutId;
        let startedAt;
        let remaining = duration;
        let dismissed = false;
        let removalHandled = false;
        let isHovered = notification.matches(":hover");
        let isFocused = notification.contains(document.activeElement);

        if (fallback) {
            fallback.hidden = true;
        }

        function restoreFallback() {
            if (!fallback || removalHandled) {
                return;
            }
            removalHandled = true;
            fallback.setAttribute("role", "note");
            fallback.setAttribute("aria-live", "off");
            fallback.hidden = false;
        }

        function dismiss() {
            if (dismissed) {
                return;
            }
            dismissed = true;
            window.clearTimeout(timeoutId);
            timeoutId = undefined;
            notification.classList.add("is-dismissing");
            notification.addEventListener("transitionend", () => {
                notification.remove();
                restoreFallback();
            }, {
                once: true,
            });
            window.setTimeout(() => {
                notification.remove();
                restoreFallback();
            }, 300);
        }

        function startTimer() {
            if (!dismissed && !isHovered && !isFocused && !timeoutId && remaining > 0) {
                startedAt = Date.now();
                timeoutId = window.setTimeout(dismiss, remaining);
            }
        }

        function pauseTimer() {
            if (dismissed || !timeoutId) {
                return;
            }
            window.clearTimeout(timeoutId);
            timeoutId = undefined;
            remaining = Math.max(0, remaining - (Date.now() - startedAt));
        }

        function updateTimer() {
            if (isHovered || isFocused) {
                pauseTimer();
            } else {
                startTimer();
            }
        }

        closeButton?.addEventListener("click", dismiss);
        notification.addEventListener("mouseenter", () => {
            isHovered = true;
            updateTimer();
        });
        notification.addEventListener("mouseleave", () => {
            isHovered = false;
            updateTimer();
        });
        notification.addEventListener("focusin", () => {
            isFocused = true;
            updateTimer();
        });
        notification.addEventListener("focusout", (event) => {
            if (!notification.contains(event.relatedTarget)) {
                isFocused = false;
                updateTimer();
            }
        });

        startTimer();
    });
})();
