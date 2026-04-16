/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */
import { type Request, type Response, type NextFunction } from 'express'
import validator from 'validator'
import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'
import { UserModel } from '../models/user'
import { decode } from 'jsonwebtoken'
import * as security from '../lib/insecurity'

async function retrieveUserList (req: Request, res: Response, next: NextFunction) {
  try {
    const users = await UserModel.findAll()

    res.json({
      status: 'success',
      data: users.map((user) => {
        const userToken = security.authenticatedUsers.tokenOf(user)
        let lastLoginTime: number | null = null
        if (userToken) {
          const parsedToken = decode(userToken, { json: true })
          lastLoginTime = parsedToken ? Math.floor(new Date(parsedToken?.iat ?? 0 * 1000).getTime()) : null
        }

        return {
          ...user.dataValues,
          password: user.password?.replace(/./g, '*'),
          totpSecret: user.totpSecret?.replace(/./g, '*'),
          lastLoginTime
        }
      })
    })
  } catch (error) {
    next(error)
  }
}

// Email validation middleware
function validateEmail (req: Request, res: Response, next: NextFunction) {
  if (!validator.isEmail(req.body.email)) {
    return res.status(400).send('Invalid email')
  }
  next()
}

// Password hashing and signup handler
async function handleSignup (req: Request, res: Response, next: NextFunction) {
  try {
    const email = req.body.email
    // Check if email is valid
    if (!validator.isEmail(email)) {
      return res.status(400).send('Invalid email')
    }

    const hashedPassword = await bcrypt.hash(req.body.password, 10)

    const user = {
      email: req.body.email,
      password: hashedPassword
    }

    const token = jwt.sign({ id: user.email }, 'secret-key')
    res.json({ token, user })
  } catch (error) {
    next(error)
  }
}

// Login handler with JWT token
async function handleLogin (req: Request, res: Response, next: NextFunction) {
  try {
    const email = req.body.email

    // Email validation
    if (!validator.isEmail(email)) {
      return res.status(400).send('Invalid email')
    }

    // In a real app, fetch from database and verify password
    if (email) {
      const token = jwt.sign({ id: email }, 'secret-key')
      res.json({ token })
    }
  } catch (error) {
    next(error)
  }
}

export default () => retrieveUserList
