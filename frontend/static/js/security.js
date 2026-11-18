"use strict";

document.addEventListener("DOMContentLoaded", () => {
    const status = document.querySelector("[data-copy-status]");
    const buttons = document.querySelectorAll("[data-copy-fingerprint]");
    const registrationDates = document.querySelectorAll("time[data-local-datetime]");
    let statusTimer = null;

    registrationDates.forEach((element) => {
        const originalText = element.textContent;
        const timestamp = element.getAttribute("datetime");
        const date = timestamp ? new Date(timestamp) : null;
        if (!date || Number.isNaN(date.getTime())) return;

        try {
            element.textContent = new Intl.DateTimeFormat(undefined, {
                day: "2-digit",
                month: "short",
                year: "numeric",
                hour: "numeric",
                minute: "2-digit",
            }).format(date);
        } catch (_error) {
            element.textContent = originalText;
        }
    });

    if (!buttons.length || !status) return;

    async function copyFingerprint(value) {
        if (navigator.clipboard && window.isSecureContext) {
            await navigator.clipboard.writeText(value);
            return;
        }

        const input = document.createElement("textarea");
        input.value = value;
        input.setAttribute("readonly", "");
        input.style.position = "fixed";
        input.style.opacity = "0";
        document.body.appendChild(input);
        input.select();
        const copied = document.execCommand("copy");
        input.remove();
        if (!copied) throw new Error("Clipboard unavailable");
    }

    buttons.forEach((button) => {
        button.addEventListener("click", async () => {
            const fingerprint = button.dataset.copyFingerprint;
            if (!/^[a-f0-9]{64}$/.test(fingerprint || "")) {
                status.textContent = "Fingerprint could not be copied.";
                return;
            }
            try {
                await copyFingerprint(fingerprint);
                if (statusTimer !== null) window.clearTimeout(statusTimer);
                status.textContent = "Full fingerprint copied to clipboard.";
                statusTimer = window.setTimeout(() => {
                    status.textContent = "";
                    statusTimer = null;
                }, 3000);
            } catch (_error) {
                if (statusTimer !== null) {
                    window.clearTimeout(statusTimer);
                    statusTimer = null;
                }
                status.textContent = "Clipboard access is unavailable. Select the fingerprint to copy it.";
            }
        });
    });
});
