const postsList = document.getElementById('posts');

// ---------------------
// CREATE
// ---------------------
async function createPost() {
    const input = document.getElementById('newPost');
    const post = input.value.trim();
    if (!post) return;

    const res = await fetch('/posts', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ post })
    });

    if (res.ok) location.reload();
    else alert('Failed to create post');
}

// ---------------------
// EDIT
// ---------------------
async function editPost(id, button) {
    const li = button.parentElement;
    const span = li.querySelector('.post-text');
    const newText = prompt('Edit post:', span.textContent);
    if (!newText) return;

    const res = await fetch('/posts/' + id, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ post: newText })
    });

    if (res.ok) span.textContent = newText;
    else alert('Failed to edit post');
}

// ---------------------
// DELETE
// ---------------------
async function deletePost(id, button) {
    if (!confirm('Delete this post?')) return;

    const res = await fetch('/posts/' + id, { method: 'DELETE' });
    if (res.ok) button.parentElement.remove();
    else alert('Failed to delete post');
}


const isValid = (input) => {
  const regex = /^[a-z0-9._]+$/i; 
  return regex.test(input);
};