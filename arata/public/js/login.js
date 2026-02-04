async function doLogin(mode) {
  const username = document.getElementById('username').value;
  const password = document.getElementById('password').value;

  try {
    const res = await fetch('/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password, mode }),
      credentials: 'same-origin'
    });

    const data = await res.json();
    if (res.ok) {
      alert(`Logged in using ${data.method}`);
    } else {
      alert(data.error || 'Login failed');
    }
  } catch (err) {
    console.error(err);
    alert('Network or server error');
  }
}

document.getElementById('loginSession').addEventListener('click', () => doLogin('session'));
document.getElementById('loginJwt').addEventListener('click', () => doLogin('jwt'));
