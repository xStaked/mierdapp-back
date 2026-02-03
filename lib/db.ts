import pg from 'pg'
const { Pool } = pg

export const db = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes('localhost') || process.env.DATABASE_URL?.includes('127.0.0.1') ? false : { rejectUnauthorized: false }
})

export const isDbReady = (): boolean => !!process.env.DATABASE_URL
