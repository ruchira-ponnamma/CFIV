(() => {
    const fileInput = document.querySelector("#file-input");
    const dropzone = document.querySelector("#file-dropzone");
    const selectedFile = document.querySelector("#selected-file");

    if (!fileInput || !dropzone || !selectedFile) {
        return;
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

    function displaySelectedFile(file) {
        if (!file) {
            selectedFile.textContent = "No file selected";
            selectedFile.classList.remove("has-file");
            return;
        }

        selectedFile.textContent = `${file.name} · ${formatFileSize(file.size)}`;
        selectedFile.classList.add("has-file");
    }

    fileInput.addEventListener("change", () => {
        displaySelectedFile(fileInput.files[0]);
    });

    ["dragenter", "dragover"].forEach((eventName) => {
        dropzone.addEventListener(eventName, (event) => {
            event.preventDefault();
            dropzone.classList.add("is-dragging");
        });
    });

    ["dragleave", "drop"].forEach((eventName) => {
        dropzone.addEventListener(eventName, (event) => {
            event.preventDefault();
            dropzone.classList.remove("is-dragging");
        });
    });

    dropzone.addEventListener("drop", (event) => {
        const [file] = event.dataTransfer.files;
        if (!file || typeof DataTransfer === "undefined") {
            return;
        }

        const transfer = new DataTransfer();
        transfer.items.add(file);
        fileInput.files = transfer.files;
        displaySelectedFile(file);
    });
})();
