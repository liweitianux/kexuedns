// SPDX-License-Identifier: MIT
//
// Kexue DNS - WebUI JavaScript code.
//

"use strict";

async function getVersionInfo() {
    const url = "/api/version";
    try {
        const response = await fetch(url);
        if (!response.ok) {
          throw new Error(`Response status: ${response.status}`);
        }
        const vi = await response.json();
        document.getElementById("version").textContent = vi.version;
        document.getElementById("versionDate").textContent = `(${vi.date})`;
    } catch (error) {
        console.error(error.message);
    }
};

document.addEventListener("DOMContentLoaded", () => {
    getVersionInfo();
});
