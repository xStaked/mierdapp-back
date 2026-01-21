import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import { type Request, type Response, type NextFunction } from 'express'

const JWT_SECRET: string = process.env.JWT_SECRET || 'default_secret_change_in_production'
const JWT_EXPIRES_IN = '24h'

interface JwtPayload {
  id: string
  username: string
}

export interface AuthRequest extends Request {
  user?: JwtPayload
}

export const hashPassword = async (password: string): Promise<string> => {
  const salt = await bcrypt.genSalt(10)
  return bcrypt.hash(password, salt)
}

export const comparePassword = async (password: string, hash: string): Promise<boolean> => {
  return bcrypt.compare(password, hash)
}

export const generateToken = (userId: string, username: string): string => {
  return jwt.sign({ id: userId, username }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN })
}

export const authMiddleware = (req: AuthRequest, res: Response, next: NextFunction) => {
  const authHeader = req.headers.authorization

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authorization token required' })
  }

  const token = authHeader.split(' ')[1]
  if (!token) {
    return res.status(401).json({ error: 'Authorization token required' })
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET) as unknown as JwtPayload
    req.user = decoded
    next()
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' })
  }
}
