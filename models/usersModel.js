import bcrypt from "bcryptjs";
import pool from "/connection.js"

const SALT_ROUNDS = 12;

export default class User {
  // 🔒 private fields (true privacy, not accessible outside the class)
  #id;
  #username;
  #email;
  #passwordHash;
  #createdAt;
  #isMod;

  constructor(row) {
    this.#id = row.id;
    this.#username = row.username;
    this.#email = row.email;
    this.#passwordHash = row.password_hash;
    this.#createdAt = row.created_at;
    this.#isMod = row.is_mod || false;

    // ❄️ prevents adding/modifying public properties
    Object.freeze(this);
  }

  get id() { return this.#id; }
  get username() { return this.#username; }
  get email() { return this.#email; }
  get createdAt() { return this.#createdAt; }
  get isMod() { return this.#isMod; } 

  /* ----------------- Auth helpers ----------------- */
  async verifyPassword(plainPassword) {
    return bcrypt.compare(plainPassword, this.#passwordHash);
  }

  toSafeObject() {
    return {
      id: this.#id,
      username: this.#username,
      email: this.#email,
      createdAt: this.#createdAt
    };
  }

  /* ----------------- Static DB methods ----------------- */

  static async hashPassword(password) {
    return bcrypt.hash(password, SALT_ROUNDS);
  }

  static async create({ username, email, password }) {
    const passwordHash = await this.hashPassword(password);

    const { rows } = await pool.query(
      `
      INSERT INTO users (username, email, password_hash)
      VALUES ($1, $2, $3)
      RETURNING *
      `,
      [username, email, passwordHash]
    );

    return new User(rows[0]);
  }

  static async createAdmin({ username, email, password }) {

    const passwordHash = await this.hashPassword(password);
    const { rows } = await pool.query(
      `
      INSERT INTO users (username, email, password_hash, is_mod)
      VALUES ($1, $2, $3, true)
      RETURNING *
      `,
      [username, email, passwordHash]
      );

      return new User(rows[0]);
    }


    static async makeMod(id) {
      // only for internal/admin scripts
      await pool.query(
        "UPDATE users SET is_mod = true WHERE id = $1",
        [id]
      );
    }
  

  static async findById(id) {
    const { rows } = await pool.query(
      "SELECT * FROM users WHERE id = $1",
      [id]
    );

    return rows[0] ? new User(rows[0]) : null;
  }

  static async findByEmail(email) {
    const { rows } = await pool.query(
      "SELECT * FROM users WHERE email = $1",
      [email]
    );

    return rows[0] ? new User(rows[0]) : null;
  }

  static async deleteById(id) {
    await pool.query("DELETE FROM users WHERE id = $1", [id]);
  }
}
