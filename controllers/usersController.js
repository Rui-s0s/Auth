import User from '../models/usersModel.js';
import crypto from "crypto"

export async function showLogin(req, res) {
  try {
      res.render('login')
    } catch (err) {
      console.error(err)
      res.sendStatus(500)
    }
}

export async function showRegister(req, res) {
  try {
    res.render('register')
  } catch (err) {
    console.error(err)
    res.sendStatus(500)
  }
}

export async function login(req, res) {
  const { username, password } = req.body;


  if (!username || !password)
  return res.status(400).json({ error: "Username and password required" });

  try {
    // Auth.something
    // search for user if it exists and credentials
    const sessionId = crypto.randomUUID
  } catch (err) {
    console.error(err)
    res.sendStatus(500)
  }
}

export async function register(req, res) {
  try {
    // Auth.something
  } catch (err) {
    console.error(err)
    res.sendStatus(500)
  }
}

export async function logout(req, res) {
  try {
    // Auth.something
    res.sendStatus(200)
  } catch (err) {
    console.error(err)
    res.sendStatus(500)
  }
}