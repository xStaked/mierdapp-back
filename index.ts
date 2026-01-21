import express, { type Request, type Response } from 'express'
import cors from 'cors'
import helmet from 'helmet'
import rateLimit from 'express-rate-limit'
import { db, isDbReady } from './lib/db.js'
import { hashPassword, comparePassword, generateToken, authMiddleware, type AuthRequest } from './lib/auth.js'
import {
  loginValidator,
  registerValidator,
  poopLogValidator,
  friendRequestValidator,
  friendRespondValidator,
  searchValidator,
  uuidParamValidator
} from './lib/validators.js'
import type {
  UserRow,
  PoopLogRow,
  FriendshipRow,
} from './lib/types.js'

const app = express()

// Security Headers
app.use(helmet())

// CORS Configuration
const allowedOrigins = process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000', 'http://localhost:5173']
app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true)
    } else {
      callback(new Error('Not allowed by CORS'))
    }
  },
  credentials: true
}))

// Request parsing with size limit
app.use(express.json({ limit: '100kb' }))

// Rate Limiting
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: 'Too many requests, please try again later.' }
})

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10, // Slightly higher for dev
  message: { error: 'Too many auth attempts, please try again later.' }
})

app.use('/api/', generalLimiter)
app.use('/api/auth/', authLimiter)

const isValidUUID = (id: any): boolean => {
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
  return typeof id === 'string' && uuidRegex.test(id)
}

// Auth / Login
app.post('/api/auth/login', loginValidator, async (req: Request, res: Response) => {
  try {
    const { username, password } = req.body
    console.log('Login attempt:', username)

    // Check if user exists
    const existing = await db.query(
      'SELECT * FROM users WHERE username = $1',
      [username.toLowerCase()]
    )

    if (existing.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' })
    }

    const user = existing.rows[0]

    // Check if account is deleted
    if (user.deleted_at) {
      return res.status(403).json({ error: 'Account has been deleted' })
    }

    // Verify password
    if (!user.password_hash) {
      return res.status(400).json({ error: 'User has no password set. Please re-register.' })
    }

    const isValidPassword = await comparePassword(password, user.password_hash)
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid password' })
    }

    const token = generateToken(user.id, user.username)
    res.json({ user: { id: user.id, username: user.username, display_name: user.display_name }, token })
  } catch (err) {
    console.error('Login error:', err)
    res.status(500).json({ error: 'Login failed' })
  }
})

// Auth / Delete Account (Soft Delete)
app.delete('/api/auth/account', authMiddleware, async (req: AuthRequest, res: Response) => {
  try {
    if (!isDbReady()) {
      return res.status(503).json({ error: 'Database not configured' })
    }

    const userId = req.user!.id

    // Soft delete the user by setting deleted_at timestamp
    const result = await db.query(
      `UPDATE users 
       SET deleted_at = NOW() 
       WHERE id = $1 AND deleted_at IS NULL
       RETURNING id, username`,
      [userId]
    ) as { rows: UserRow[] }

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found or already deleted' })
    }

    res.json({
      success: true,
      message: 'Account deleted successfully',
      deletedUser: {
        id: result.rows[0]!.id,
        username: result.rows[0]!.username
      }
    })
  } catch (err) {
    console.error('Delete account error:', err)
    res.status(500).json({ error: 'Failed to delete account' })
  }
})

// Auth / Register
app.post('/api/auth/register', registerValidator, async (req: Request, res: Response) => {
  try {
    if (!isDbReady()) {
      return res.status(503).json({ error: 'Database not configured' })
    }

    const { username, displayName, password } = req.body
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' })
    }

    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' })
    }

    // Check if user exists
    const existing = await db.query(
      'SELECT * FROM users WHERE username = $1',
      [username.toLowerCase()]
    )

    if (existing.rows.length > 0) {
      return res.status(400).json({ error: 'Username already taken' })
    }

    // Hash password
    const passwordHash = await hashPassword(password)

    // Create new user
    const result = await db.query(
      `INSERT INTO users (username, display_name, password_hash, created_at)
       VALUES ($1, $2, $3, NOW())
       RETURNING id, username, display_name, created_at`,
      [username.toLowerCase(), displayName || username, passwordHash]
    ) as { rows: UserRow[] }

    const user = result.rows[0]
    if (!user) throw new Error('Failed to create user')
    const token = generateToken(user.id, user.username)
    res.status(201).json({ user: { id: user.id, username: user.username, display_name: user.display_name, created_at: user.created_at }, token })
  } catch (err) {
    console.error('Registration error:', err)
    res.status(500).json({ error: 'Registration failed' })
  }
})

// Get poop logs
app.get('/api/poops', authMiddleware, async (req: AuthRequest, res: Response) => {
  try {
    if (!isDbReady()) {
      return res.json({ logs: [] })
    }

    const userId = req.user!.id

    const result = await db.query(
      `SELECT * FROM poop_logs
       WHERE user_id = $1
       ORDER BY timestamp DESC
       LIMIT 100`,
      [userId]
    ) as { rows: PoopLogRow[] }

    res.json({ logs: result.rows })
  } catch (err) {
    console.error('Get poops error:', err)
    res.json({ logs: [] })
  }
})

// Log a poop
app.post('/api/poops', authMiddleware, poopLogValidator, async (req: AuthRequest, res: Response) => {
  try {
    if (!isDbReady()) {
      return res.status(503).json({ error: 'Database not configured' })
    }

    const userId = req.user!.id
    const {
      notes, latitude, longitude,
      locationName, photoUrl, rating, durationMinutes
    } = req.body

    const result = await db.query(
      `INSERT INTO poop_logs (
        user_id, timestamp, notes, latitude, longitude,
        location_name, photo_url, rating, duration_minutes
      )
       VALUES ($1, NOW(), $2, $3, $4, $5, $6, $7, $8)
       RETURNING *`,
      [
        userId, notes || null, latitude || null, longitude || null,
        locationName || null, photoUrl || null, rating || null, durationMinutes || null
      ]
    ) as { rows: PoopLogRow[] }

    res.json({ log: result.rows[0] })
  } catch (err) {
    console.error('Log poop error:', err)
    res.status(500).json({ error: 'Failed to log' })
  }
})

// Update a poop
app.put('/api/poops/:id', authMiddleware, ...uuidParamValidator('id'), poopLogValidator, async (req: AuthRequest, res: Response) => {
  try {
    if (!isDbReady()) return res.status(503).json({ error: 'Database not ready' })

    const { id } = req.params
    const userId = req.user!.id

    const fields = req.body
    const setClause: string[] = []
    const values: any[] = []
    let i = 1

    const fieldMap: Record<string, string> = {
      notes: 'notes',
      latitude: 'latitude',
      longitude: 'longitude',
      locationName: 'location_name',
      photoUrl: 'photo_url',
      rating: 'rating',
      durationMinutes: 'duration_minutes'
    }

    for (const [key, dbColumn] of Object.entries(fieldMap)) {
      if (fields[key] !== undefined) {
        setClause.push(`${dbColumn} = $${i++}`)
        values.push(fields[key])
      }
    }

    if (setClause.length === 0) {
      return res.status(400).json({ error: 'No fields to update' })
    }

    values.push(id, userId)
    const query = `UPDATE poop_logs SET ${setClause.join(', ')} WHERE id = $${i} AND user_id = $${i + 1} RETURNING *`
    const result = await db.query(query, values) as { rows: PoopLogRow[] }

    if (result.rows.length === 0) return res.status(404).json({ error: 'Poop not found' })
    res.json({ log: result.rows[0] })
  } catch (err) {
    console.error('Update poop error:', err)
    res.status(500).json({ error: 'Update failed' })
  }
})

// Delete a poop
app.delete('/api/poops/:id', authMiddleware, ...uuidParamValidator('id'), async (req: AuthRequest, res: Response) => {
  try {
    if (!isDbReady()) return res.status(503).json({ error: 'Database not ready' })

    const { id } = req.params
    const userId = req.user!.id

    const result = await db.query(
      `DELETE FROM poop_logs WHERE id = $1 AND user_id = $2 RETURNING *`,
      [id, userId]
    ) as { rows: PoopLogRow[] }

    if (result.rows.length === 0) return res.status(404).json({ error: 'Poop not found' })
    res.json({ success: true, message: 'Poop deleted' })
  } catch (err) {
    console.error('Delete poop error:', err)
    res.status(500).json({ error: 'Delete failed' })
  }
})

// Get stats
app.get('/api/stats', authMiddleware, async (req: AuthRequest, res: Response) => {
  try {
    if (!isDbReady()) {
      return res.json({
        today: 0,
        week: 0,
        month: 0,
        allTime: 0,
        currentStreak: 0,
        longestStreak: 0,
        avgPerDay: 0,
        dailyData: []
      })
    }

    const userId = req.user!.id

    // Today count
    const todayResult = await db.query(
      `SELECT COUNT(*) as count FROM poop_logs 
       WHERE user_id = $1 AND DATE(timestamp) = CURRENT_DATE`,
      [userId]
    )

    // Week count
    const weekResult = await db.query(
      `SELECT COUNT(*) as count FROM poop_logs 
       WHERE user_id = $1 AND timestamp >= DATE_TRUNC('week', CURRENT_DATE)`,
      [userId]
    )

    // Month count
    const monthResult = await db.query(
      `SELECT COUNT(*) as count FROM poop_logs 
       WHERE user_id = $1 AND timestamp >= DATE_TRUNC('month', CURRENT_DATE)`,
      [userId]
    )

    // All time count
    const allTimeResult = await db.query(
      `SELECT COUNT(*) as count FROM poop_logs WHERE user_id = $1`,
      [userId]
    )

    // Daily data for last 30 days
    const dailyDataResult = await db.query(
      `SELECT DATE(timestamp) as date, COUNT(*) as count 
       FROM poop_logs 
       WHERE user_id = $1 AND timestamp >= CURRENT_DATE - INTERVAL '30 days'
       GROUP BY DATE(timestamp)
       ORDER BY date DESC`,
      [userId]
    )

    // Calculate streak
    const streakResult = await db.query(
      `SELECT DISTINCT DATE(timestamp) as date 
       FROM poop_logs 
       WHERE user_id = $1 
       ORDER BY date DESC`,
      [userId]
    ) as { rows: Array<{ date: string | Date }> }

    let currentStreak = 0
    let longestStreak = 0
    let tempStreak = 0
    const today = new Date()
    today.setHours(0, 0, 0, 0)

    const dates = streakResult.rows.map((r: { date: string | Date }) => {
      const d = new Date(r.date)
      d.setHours(0, 0, 0, 0)
      return d.getTime()
    })

    // Calculate current streak
    let checkDate = today.getTime()
    for (let i = 0; i < dates.length; i++) {
      const currentDate = dates[i]
      if (currentDate === undefined) break;

      if (currentDate === checkDate) {
        currentStreak++
        checkDate -= 86400000 // subtract one day
      } else if (currentDate === checkDate - 86400000 && i === 0) {
        // Allow if today has no logs but yesterday does
        checkDate = currentDate
        currentStreak++
        checkDate -= 86400000
      } else {
        break
      }
    }

    // Calculate longest streak
    tempStreak = 1
    for (let i = 1; i < dates.length; i++) {
      const prevDate = dates[i - 1]
      const currentDate = dates[i]
      if (prevDate === undefined || currentDate === undefined) break;

      if (prevDate - currentDate === 86400000) {
        tempStreak++
      } else {
        longestStreak = Math.max(longestStreak, tempStreak)
        tempStreak = 1
      }
    }
    longestStreak = Math.max(longestStreak, tempStreak, currentStreak)

    // Calculate average per day
    const firstLogResult = await db.query(
      `SELECT MIN(timestamp) as first FROM poop_logs WHERE user_id = $1`,
      [userId]
    ) as { rows: Array<{ first: string | Date | null }> }

    let avgPerDay = 0
    if (firstLogResult.rows[0]?.first) {
      const daysSinceFirst = Math.max(1, Math.ceil(
        (Date.now() - new Date(firstLogResult.rows[0].first).getTime()) / 86400000
      ))
      avgPerDay = parseInt(allTimeResult.rows[0].count) / daysSinceFirst
    }

    res.json({
      today: parseInt(todayResult.rows[0].count),
      week: parseInt(weekResult.rows[0].count),
      month: parseInt(monthResult.rows[0].count),
      allTime: parseInt(allTimeResult.rows[0].count),
      currentStreak,
      longestStreak,
      avgPerDay,
      dailyData: dailyDataResult.rows.map((r: { date: string | Date, count: string }) => ({
        date: String(r.date),
        count: parseInt(r.count)
      }))
    })
  } catch (err) {
    console.error('Stats error:', err)
    res.json({
      today: 0,
      week: 0,
      month: 0,
      allTime: 0,
      currentStreak: 0,
      longestStreak: 0,
      avgPerDay: 0,
      dailyData: []
    })
  }
})

// Get friends
app.get('/api/friends', authMiddleware, async (req: AuthRequest, res: Response) => {
  try {
    if (!isDbReady()) {
      return res.json({ friends: [] })
    }

    const userId = req.user!.id

    const result = await db.query(
      `SELECT f.*, u.id as user_id, u.username, u.display_name,
              (SELECT COUNT(*) FROM poop_logs WHERE user_id = u.id AND DATE(timestamp) = CURRENT_DATE) as today_count,
              (SELECT COUNT(*) FROM poop_logs WHERE user_id = u.id AND timestamp >= DATE_TRUNC('week', CURRENT_DATE)) as week_count
       FROM friendships f
       JOIN users u ON (f.user_id = $1 AND f.friend_id = u.id) OR (f.friend_id = $1 AND f.user_id = u.id AND f.status = 'accepted')
       WHERE (f.user_id = $1 OR f.friend_id = $1)
       AND u.id != $1`,
      [userId]
    ) as { rows: FriendshipRow[] }

    const friends = result.rows.map((row: FriendshipRow) => ({
      id: row.id,
      user: {
        id: row.user_id,
        username: row.username,
        displayName: row.display_name
      },
      status: row.status,
      todayCount: parseInt(String(row.today_count || 0)),
      weekCount: parseInt(String(row.week_count || 0)),
      streakCount: 0 // Would need additional calculation
    }))

    res.json({ friends })
  } catch (err) {
    console.error('Friends error:', err)
    res.json({ friends: [] })
  }
})

// Send friend request
app.post('/api/friends/request', authMiddleware, friendRequestValidator, async (req: AuthRequest, res: Response) => {
  try {
    if (!isDbReady()) {
      return res.status(503).json({ error: 'Database not configured' })
    }

    const userId = req.user!.id
    const { friendUsername } = req.body

    // Find friend by username
    const friendResult = await db.query(
      'SELECT id FROM users WHERE username = $1',
      [friendUsername.toLowerCase()]
    ) as { rows: UserRow[] }

    if (friendResult.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' })
    }

    const friendId = friendResult.rows[0]!.id

    if (friendId === userId) {
      return res.status(400).json({ error: 'Cannot add yourself' })
    }

    // Check if friendship exists
    const existingResult = await db.query(
      `SELECT * FROM friendships 
       WHERE (user_id = $1 AND friend_id = $2) OR (user_id = $2 AND friend_id = $1)`,
      [userId, friendId]
    ) as { rows: FriendshipRow[] }

    if (existingResult.rows.length > 0) {
      return res.status(400).json({ error: 'Friendship already exists' })
    }

    // Create friendship request
    await db.query(
      `INSERT INTO friendships (user_id, friend_id, status, created_at)
       VALUES ($1, $2, 'pending', NOW())`,
      [userId, friendId]
    )

    res.json({ success: true })
  } catch (err) {
    console.error('Friend request error:', err)
    res.status(500).json({ error: 'Failed to send request' })
  }
})

// Get pending friend requests (requests I haven't responded to)
app.get('/api/friends/requests/pending', authMiddleware, async (req: AuthRequest, res: Response) => {
  try {
    if (!isDbReady()) {
      return res.json({ requests: [] })
    }

    const userId = req.user!.id

    // Get all pending friend requests where current user is the recipient
    const result = await db.query(
      `SELECT f.id as friendship_id, f.created_at,
              u.id as user_id, u.username, u.display_name
       FROM friendships f
       JOIN users u ON f.user_id = u.id
       WHERE f.friend_id = $1 AND f.status = 'pending'
       ORDER BY f.created_at DESC`,
      [userId]
    ) as { rows: FriendshipRow[] }

    const requests = result.rows.map((row: any) => ({
      friendshipId: row.friendship_id,
      createdAt: row.created_at,
      requester: {
        id: row.user_id,
        username: row.username,
        displayName: row.display_name
      }
    }))

    res.json({ requests })
  } catch (err) {
    console.error('Get pending requests error:', err)
    res.json({ requests: [] })
  }
})

// Respond to friend request
app.post('/api/friends/respond', authMiddleware, friendRespondValidator, async (req: AuthRequest, res: Response) => {
  try {
    if (!isDbReady()) {
      return res.status(503).json({ error: 'Database not configured' })
    }

    const userId = req.user!.id
    const { friendshipId, accept } = req.body

    if (accept) {
      await db.query(
        `UPDATE friendships SET status = 'accepted' WHERE id = $1 AND friend_id = $2`,
        [friendshipId, userId]
      )
    } else {
      await db.query(
        `DELETE FROM friendships WHERE id = $1 AND friend_id = $2`,
        [friendshipId, userId]
      )
    }

    res.json({ success: true })
  } catch (err) {
    console.error('Friend respond error:', err)
    res.status(500).json({ error: 'Failed to respond' })
  }
})

// Get friend's poop logs (only if friendship is accepted)
app.get('/api/friends/:friendId/poops', authMiddleware, ...uuidParamValidator('friendId'), async (req: AuthRequest, res: Response) => {
  try {
    if (!isDbReady()) {
      return res.json({ logs: [] })
    }

    const userId = req.user!.id
    const { friendId } = req.params

    // Verify friendship exists and is accepted
    const friendshipResult = await db.query(
      `SELECT * FROM friendships
       WHERE ((user_id = $1 AND friend_id = $2) OR (user_id = $2 AND friend_id = $1))
       AND status = 'accepted'`,
      [userId, friendId]
    ) as { rows: FriendshipRow[] }

    if (friendshipResult.rows.length === 0) {
      return res.status(403).json({ error: 'Not friends with this user' })
    }

    const result = await db.query(
      `SELECT * FROM poop_logs
       WHERE user_id = $1
       ORDER BY timestamp DESC
       LIMIT 100`,
      [friendId]
    ) as { rows: PoopLogRow[] }

    res.json({ logs: result.rows })
  } catch (err) {
    console.error('Get friend poops error:', err)
    res.json({ logs: [] })
  }
})

// Get all poops from user and friends (for map view)
app.get('/api/poops/feed', authMiddleware, async (req: AuthRequest, res: Response) => {
  try {
    if (!isDbReady()) {
      return res.json({ logs: [] })
    }

    const userId = req.user!.id
    const { filter } = req.query // 'all' | 'me' | 'friends' | friendId

    console.log('Feed request - userId:', userId, 'filter:', filter)

    let query: string
    let params: any[]

    if (filter === 'me') {
      query = `SELECT p.*, u.username, u.display_name
               FROM poop_logs p
               JOIN users u ON p.user_id = u.id
               WHERE p.user_id = $1
               ORDER BY p.timestamp DESC
               LIMIT 200`
      params = [userId]
    } else if (filter === 'friends') {
      query = `SELECT p.*, u.username, u.display_name
               FROM poop_logs p
               JOIN users u ON p.user_id = u.id
               WHERE p.user_id IN (
                 SELECT CASE WHEN user_id = $1 THEN friend_id ELSE user_id END
                 FROM friendships
                 WHERE (user_id = $1 OR friend_id = $1) AND status = 'accepted'
               )
               ORDER BY p.timestamp DESC
               LIMIT 200`
      params = [userId]
    } else if (filter && isValidUUID(filter as string)) {
      // Specific friend
      const friendId = filter as string
      // Verify friendship
      const friendshipResult = await db.query(
        `SELECT * FROM friendships
         WHERE ((user_id = $1 AND friend_id = $2) OR (user_id = $2 AND friend_id = $1))
         AND status = 'accepted'`,
        [userId, friendId]
      )
      if (friendshipResult.rows.length === 0) {
        return res.status(403).json({ error: 'Not friends with this user' })
      }
      query = `SELECT p.*, u.username, u.display_name
               FROM poop_logs p
               JOIN users u ON p.user_id = u.id
               WHERE p.user_id = $1
               ORDER BY p.timestamp DESC
               LIMIT 200`
      params = [friendId]
    } else {
      // 'all' or no filter - user + all friends
      query = `SELECT p.*, u.username, u.display_name
               FROM poop_logs p
               JOIN users u ON p.user_id = u.id
               WHERE p.user_id = $1
                  OR p.user_id IN (
                    SELECT CASE WHEN f.user_id = $1 THEN f.friend_id ELSE f.user_id END
                    FROM friendships f
                    WHERE (f.user_id = $1 OR f.friend_id = $1) AND f.status = 'accepted'
                  )
               ORDER BY p.timestamp DESC
               LIMIT 200`
      params = [userId]
    }

    console.log('Executing query with params:', params)
    const result = await db.query(query, params) as { rows: PoopLogRow[] }
    console.log('Query returned', result.rows.length, 'rows')

    const logs = result.rows.map((row: PoopLogRow) => ({
      ...row,
      user: {
        id: row.user_id,
        username: row.username,
        displayName: row.display_name
      }
    }))

    res.json({ logs })
  } catch (err) {
    console.error('Get feed error:', err)
    res.json({ logs: [] })
  }
})

// Search users to add as friends
app.get('/api/friends/search', authMiddleware, searchValidator, async (req: AuthRequest, res: Response) => {
  try {
    if (!isDbReady()) {
      return res.json({ users: [] })
    }

    const userId = req.user!.id
    const { query } = req.query as { query: string }

    const searchTerm = `%${query.toLowerCase()}%`

    const result = await db.query(
      `SELECT u.id, u.username, u.display_name,
              f.id as friendship_id,
              f.status as friendship_status
       FROM users u
       LEFT JOIN friendships f ON
         (f.user_id = $1 AND f.friend_id = u.id) OR
         (f.friend_id = $1 AND f.user_id = u.id)
       WHERE u.id != $1
         AND (LOWER(u.username) LIKE $2 OR LOWER(u.display_name) LIKE $2)
       ORDER BY u.username
       LIMIT 20`,
      [userId, searchTerm]
    ) as { rows: Array<FriendshipRow & { friendship_status: string }> }

    const users = result.rows.map((row: any) => ({
      id: row.id,
      username: row.username,
      displayName: row.display_name,
      friendshipStatus: (row as any).friendship_status || null
    }))

    res.json({ users })
  } catch (err) {
    console.error('Search users error:', err)
    res.status(500).json({ error: 'Search failed' })
  }
})

// Get leaderboard
app.get('/api/leaderboard', authMiddleware, async (req: AuthRequest, res: Response) => {
  try {
    if (!isDbReady()) {
      return res.json({ leaderboard: [] })
    }
    console.log('ejecutando leaderboard')
    const userId = req.user!.id

    // Get user and their friends' weekly counts
    const result = await db.query(
      `SELECT u.id, u.username, u.display_name,
              COUNT(p.id) as week_count
       FROM users u
       LEFT JOIN poop_logs p ON p.user_id = u.id
         AND p.timestamp >= DATE_TRUNC('week', CURRENT_DATE)
       WHERE u.id = $1
          OR u.id IN (
            SELECT CASE WHEN user_id = $1 THEN friend_id ELSE user_id END
            FROM friendships
            WHERE (user_id = $1 OR friend_id = $1) AND status = 'accepted'
          )
       GROUP BY u.id, u.username, u.display_name
       ORDER BY week_count DESC`,
      [userId]
    ) as { rows: Array<UserRow & { week_count: string }> }

    const leaderboard = result.rows.map((row: UserRow & { week_count: string }, index: number) => ({
      rank: index + 1,
      user: {
        id: row.id,
        username: row.username,
        displayName: row.display_name
      },
      value: parseInt(row.week_count),
      isCurrentUser: row.id === userId
    }))

    res.json({ leaderboard })
  } catch (err) {
    console.error('Leaderboard error:', err)
    res.json({ leaderboard: [] })
  }
})



const PORT = process.env.PORT || 3001
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`)
})
