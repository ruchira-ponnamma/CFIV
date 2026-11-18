(() => {
    const searchInput = document.querySelector("#my-files-search");
    const statusFilter = document.querySelector("#my-files-status");
    const rows = Array.from(document.querySelectorAll("[data-file-row]"));
    const noResults = document.querySelector("#my-files-no-results");

    function formatLocalDateTime(value) {
        const date = new Date(value);
        if (Number.isNaN(date.getTime())) {
            return value;
        }
        return date.toLocaleString(undefined, {
            dateStyle: "medium",
            timeStyle: "short",
        });
    }

    function formatFileSize(sizeBytes) {
        if (!Number.isFinite(sizeBytes) || sizeBytes < 0) {
            return "—";
        }
        if (sizeBytes < 1024) {
            return `${sizeBytes} B`;
        }
        if (sizeBytes < 1024 * 1024) {
            return `${(sizeBytes / 1024).toFixed(1)} KB`;
        }
        return `${(sizeBytes / (1024 * 1024)).toFixed(2)} MB`;
    }

    document.querySelectorAll("[data-registration-time]").forEach((timeElement) => {
        timeElement.textContent = formatLocalDateTime(timeElement.dateTime);
    });
    document.querySelectorAll("[data-file-size]").forEach((sizeElement) => {
        const sizeBytes = Number(sizeElement.dataset.fileSize);
        sizeElement.textContent = formatFileSize(sizeBytes);
    });

    if (!searchInput || !statusFilter || rows.length === 0 || !noResults) {
        return;
    }

    function filterFiles() {
        const query = searchInput.value.trim().toLocaleLowerCase();
        const selectedStatus = statusFilter.value;
        let visibleCount = 0;

        rows.forEach((row) => {
            const matchesName = row.dataset.filename.toLocaleLowerCase().includes(query);
            const matchesStatus = selectedStatus === "all" || row.dataset.status === selectedStatus;
            const isVisible = matchesName && matchesStatus;
            row.hidden = !isVisible;
            if (isVisible) {
                visibleCount += 1;
            }
        });

        noResults.hidden = visibleCount > 0;
    }

    searchInput.addEventListener("input", filterFiles);
    statusFilter.addEventListener("change", filterFiles);
})();
