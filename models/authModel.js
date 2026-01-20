export async function getById(id) {
  const { rows } = await pool.query('SELECT * FROM posts WHERE id = $1', [id])
  return rows[0]
}