const form = document.getElementById('registerForm');

form.addEventListener('submit', async (e) => {
e.preventDefault(); // stop page reload

const username = document.getElementById('username').value;
const email = document.getElementById('email').value;
const password = document.getElementById('password').value;


try {
const res = await fetch('/register', {
method: 'POST',
headers: { 'Content-Type': 'application/json' },
body: JSON.stringify({ username, email, password })
});


const data = await res.json();


if (!res.ok) {
alert(data.error || 'Registration failed');
return;
}


// success
window.location.href = '/login';


} catch (err) {
console.error(err);
alert('Server error');
}
});