import * as Post from '../models/postsModels.js'


export async function showPosts(req, res) {
  try {
    const posts = await Post.getAll()
    res.render('crud', { posts })
  } catch (err) {
    console.error(err)
    res.sendStatus(500)
  }
}

export async function createPost (req, res) {
  try {
    const newPost = await Post.createModel(req.body.post)
    res.json(newPost)
  } catch (err) {
    console.error(err)
    res.sendStatus(500)
  }
}

export async function editPost(req, res) {
  try {
    const updated = await Post.updateModel(req.params.id, req.body.post)
    if (!updated) return res.sendStatus(404)
    res.sendStatus(200)
  } catch (err) {
    console.error(err)
    res.sendStatus(500)
  }
}

export async function deletePost(req, res) {
  try {
    const deleted = await Post.deleteModel(req.params.id)
    if (!deleted) return res.sendStatus(404)
    res.sendStatus(204)
  } catch (err) {
    console.error(err)
    res.sendStatus(500)
  }
}