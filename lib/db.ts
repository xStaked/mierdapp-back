import pg from 'pg'
const { Pool } = pg

export const db = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: false
})

export const isDbReady = (): boolean => !!process.env.DATABASE_URL
