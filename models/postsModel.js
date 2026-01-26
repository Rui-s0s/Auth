import pool from './connection.js';

// create delete update etc didnt have Model inside them
export async function getAll() { 
  const { rows } = await pool.query('SELECT * FROM posts ORDER BY likes DESC')
  return rows
}

export async function getById(id) {
  const { rows } = await pool.query('SELECT * FROM posts WHERE id = $1', [id])
  return rows[0]
}

export async function createModel(post) {
  const { rows } = await pool.query(
    'INSERT INTO posts (post) VALUES ($1) RETURNING *',
    [post]
  )
  return rows[0]
}

export async function updateModel(id, post) {
  const { rowCount } = await pool.query(
    'UPDATE posts SET post = $1 WHERE id = $2',
    [post, id]
  )
  return rowCount
}

export async function deleteModel(id) {
  const { rowCount } = await pool.query(
    'DELETE FROM posts WHERE id = $1',
    [id]
  )
  return rowCount
}