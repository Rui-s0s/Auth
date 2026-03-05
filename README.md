# Auth and Security Lab

This project is a hands-on laboratory designed to explore and understand the mechanisms of authentication (sessions and tokens), authorization, and modern web security practices, specifically focusing on mitigating XSS and CSRF attacks.

## 🎯 Purpose
The main goal is to demonstrate how cookies, tokens (JWT), and sessions work in a Node.js environment, implementing different security measures to protect users and data.

## 🚀 Key Features
- **Authentication**: Dual implementation of authentication using both **Sessions** (via `express-session`) and **JSON Web Tokens (JWT)**.
- **Authorization**: Role-based access control with different levels (Admin, Logged Users, and Public).
- **Security Measures**:
  - **Password Hashing**: Uses `bcryptjs` for secure password storage.
  - **Secure Cookies**: Implements `httpOnly`, `secure`, and `sameSite` flags.
  - **XSS Protection**: Demonstrates how to sanitize inputs and use Content Security Policy (CSP).
  - **CSRF Protection**: Integrated `csurf` middleware.
  - **Rate Limiting**: Protection against brute-force attacks on the login endpoint.
  - **Security Headers**: Uses `helmet` to set various security-related HTTP headers.

## 📁 Project Structure

### Root Project (ESM)
The root directory contains a standard implementation using ES Modules and a PostgreSQL database.
- `app.js`: Main entry point (Session-based auth focus).
- `auth.js`: Standalone authentication service (JWT focus).
- `controllers/`: Business logic for posts and users.
- `models/`: Data access layer using `pg` (PostgreSQL).
- `routes/`: Express router definitions.
- `views/`: EJS templates for the UI.
- `databases.sql`: Database schema definition.

### Arata Sub-project (CommonJS)
Located in `/arata`, this is an experimental version specifically designed to test XSS payloads and compare Session vs. JWT flows in a single app.
- Includes a collection of XSS payloads in `arata.js` for testing purposes.
- Implements `playwright` for end-to-end testing of security scenarios.

## 🛠️ Technologies
- **Backend**: Node.js, Express.js
- **Database**: PostgreSQL
- **Security**: Bcryptjs, JWT, Helmet, Csurf, Express-Rate-Limit
- **Frontend**: EJS (Embedded JavaScript templates)
- **Testing**: Playwright (in `arata` directory)

## ⚙️ Setup

1. **Install Dependencies**:
   ```bash
   npm install
   # or for the experimental version
   cd arata && npm install
   ```

2. **Database Setup**:
   - Create a PostgreSQL database using the schema in `databases.sql`.
   - Configure your `.env` file with `DATABASE_URL`, `SESSION_SECRET`, and `JWT_SECRET`.

3. **Run the Application**:
   ```bash
   npm run devStart
   # or in arata
   node arata.js
   ```

## 🧪 Security Testing
The `arata` directory contains specific tests for XSS and logout functionality. You can run them using:
```bash
cd arata
npm run test:e2e
```
