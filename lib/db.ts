import { IdealaneDB } from '@idealane/node-sdk'

export const db = new IdealaneDB({
  connectionString: process.env.DATABASE_URL!,
  ssl: process.env.DATABASE_URL?.includes('localhost') ? false : { rejectUnauthorized: false }
})

export const isDbReady = (): boolean => !!process.env.DATABASE_URL
