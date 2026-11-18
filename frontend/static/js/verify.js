(() => {
    const fileSelector = document.querySelector("#registered-file");
    const selectedName = document.querySelector("#selected-name");
    const selectedDate = document.querySelector("#selected-date");
    const selectedSize = document.querySelector("#selected-size");
    const verifyButton = document.querySelector("#verify-submit");
    const verifyActionNote = document.querySelector("#verify-action-note");
    const verificationTime = document.querySelector("#verification-time");

    function formatLocalDateTime(timestamp) {
        const date = new Date(timestamp);
        if (Number.isNaN(date.getTime())) {
            return timestamp;
        }
        return date.toLocaleString(undefined, {
            dateStyle: "medium",
            timeStyle: "short",
        });
    }

    function formatFileSize(sizeBytes) {
        if (sizeBytes < 1024) {
            return `${sizeBytes} B`;
        }
        if (sizeBytes < 1024 * 1024) {
            return `${(sizeBytes / 1024).toFixed(1)} KB`;
        }
        return `${(sizeBytes / (1024 * 1024)).toFixed(2)} MB`;
    }

    if (fileSelector && selectedName && selectedDate && selectedSize) {
        function updateSelectedFile() {
            const selectedOption = fileSelector.selectedOptions[0];
            const hasSelectedFile = Boolean(selectedOption && selectedOption.value);

            if (verifyButton) {
                verifyButton.disabled = !hasSelectedFile;
            }
            if (verifyActionNote) {
                verifyActionNote.textContent = hasSelectedFile
                    ? "Ready to verify the selected file."
                    : "Select a registered file to enable verification.";
            }

            if (!hasSelectedFile) {
                selectedName.textContent = "No file selected";
                selectedDate.textContent = "\u2014";
                selectedSize.textContent = "\u2014";
                return;
            }

            const sizeBytes = Number(selectedOption.dataset.sizeBytes);
            selectedName.textContent = selectedOption.dataset.originalName || selectedOption.textContent;
            selectedDate.textContent = formatLocalDateTime(
                selectedOption.dataset.createdAt || ""
            ) || "\u2014";
            selectedSize.textContent = Number.isFinite(sizeBytes)
                ? formatFileSize(sizeBytes)
                : "\u2014";
        }

        fileSelector.addEventListener("change", updateSelectedFile);
        updateSelectedFile();
    }

    if (verificationTime) {
        verificationTime.textContent = formatLocalDateTime(
            verificationTime.dataset.timestamp || verificationTime.dateTime
        );
    }
})();
