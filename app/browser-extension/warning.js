const params = new URLSearchParams(window.location.search);
const blockedUrl = params.get("blocked") || "";
const reason = params.get("reason") || "";

document.getElementById("blocked-url").textContent = blockedUrl;
document.getElementById("reason-text").textContent = reason
  ? `Khop voi: ${reason}`
  : "";
