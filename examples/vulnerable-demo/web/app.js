const token = "ghp_demo000000000000000000";
fetch("/api/me", { headers: { Authorization: "Bearer " + token } });
