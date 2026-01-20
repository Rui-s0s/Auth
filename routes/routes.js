import express from 'express'
import * as postsController from '../controllers/postsController.js'
import * as authController from '../controllers/authController.js'
const router = express.Router()

// Render page
router.get('/', postsController.showPosts)

// API endpoints
router.post('/posts', postsController.createPost)
router.put('/posts/:id', postsController.editPost)
router.delete('/posts/:id', postsController.deletePost)
router.post('/login', authController.login)
router.post('/register', authController.register)

export default router