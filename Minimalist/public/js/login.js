const usernameInput = document.getElementById('username');
const passwordInput = document.getElementById('password');

async function login(mode) {
  const username = usernameInput.value;
  const password = passwordInput.value;

  const res = await fetch('/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password, mode }),
    credentials: 'include' // needed for session cookies
  });

  const data = await res.json();

  if (!res.ok) {
    alert(data.error);
    return;
  }

  if (mode === 'jwt') {
    // store token in memory
    window.accessToken = data.accessToken;
  }

  window.location.replace('/protected');
}

document.getElementById('loginJwt').addEventListener('click', () => login('jwt'));
document.getElementById('loginSession').addEventListener('click', () => login('session'));