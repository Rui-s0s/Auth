// SOMETHING LIKE THIS TO CHECK ADMIN OR NOT

const requireAdmin = async (req, res, next) => {
  const userId = req.user.id; // set earlier by your authorize middleware

  const result = await db.query(
    'SELECT role FROM users WHERE id = $1',
    [userId]
  );

  if (!result.rows.length) return res.sendStatus(403);

  const role = result.rows[0].role;

  if (role !== 'admin') return res.sendStatus(403);

  next();
};
