async function doLogin(mode) {
  const username = document.getElementById('username').value;
  const password = document.getElementById('password').value;

  try {
    const res = await fetch('/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify({ username, password, mode })
    });

    let data = {};
    const contentType = res.headers.get('content-type');

    if (contentType && contentType.includes('application/json')) {
      data = await res.json();
    } else {
      data.error = await res.text();
    }

    if (res.status === 429) {
      alert(data.error || 'Too many login attempts. Try again later.');
      return;
    }

    if (!res.ok) {
      alert(data.error || 'Invalid username or password');
      return;
    }

    alert(`Logged in using ${data.method}`);
    window.location.href = '/dashboard';

  } catch (err) {
    console.error(err);
    alert('Network error. Please try again.');
  }
}

// Add event listeners to buttons
document.getElementById('loginSession').addEventListener('click', () => doLogin('session'));
document.getElementById('loginJwt').addEventListener('click', () => doLogin('jwt'));
