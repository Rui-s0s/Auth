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

// ---------------------
// LIKE (optimistic UI + reorder)
// ---------------------
async function likePost(id, button) {
    const li = button.parentElement;
    const likesSpan = li.querySelector('.likes');
    const currentLikes = Number(likesSpan.textContent.replace(/\D/g,''));

    // Optimistic update
    const newLikes = currentLikes + 1;
    likesSpan.textContent = 'Likes: ' + newLikes;
    li.dataset.likes = newLikes;
    button.disabled = true;

    try {
    const res = await fetch('/posts/' + id + '/like', { method: 'POST' });
    if (!res.ok) throw new Error();

    // Reorder posts list in descending order
    reorderPost(li);
    } catch {
    // Rollback if failed
    likesSpan.textContent = 'Likes: ' + currentLikes;
    li.dataset.likes = currentLikes;
    alert('Failed to like post');
    } finally {
    button.disabled = false;
    }
}

function reorderPost(li) {
    const newLikes = Number(li.dataset.likes);

    let inserted = false;
    for (const otherLi of postsList.children) {
    if (otherLi === li) continue;
    const otherLikes = Number(otherLi.dataset.likes);
    if (newLikes > otherLikes) {
        postsList.insertBefore(li, otherLi);
        inserted = true;
        break;
    }
    }

    if (!inserted) {
    postsList.appendChild(li);
    }
}

const isValid = (input) => {
  const regex = /^[a-z0-9._]+$/i; 
  return regex.test(input);
};