import * as Auth from '../models/authModels.js'

export async function login(req, res) {
  try {
    // Auth.something
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