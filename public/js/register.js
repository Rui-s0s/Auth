document.getElementById("registerForm").addEventListener("submit", async e => {
  e.preventDefault();

  const body = {
    username: username.value,
    email: email.value,
    password: password.value
  };

  const res = await fetch("/auth/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  });

  const data = await res.json();
  alert(data.registered ? "Registered!" : data.error);
});