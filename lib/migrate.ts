import fs from 'fs'
import path from 'path'
import { db } from './db.js'

export const runMigrations = async () => {
    const migrationsDir = path.join(process.cwd(), 'migrations')
    if (!fs.existsSync(migrationsDir)) {
        console.log('No migrations directory found.')
        return
    }

    const files = fs.readdirSync(migrationsDir).sort()

    // Ensure we have a migrations table to track progress
    await db.query(`
    CREATE TABLE IF NOT EXISTS _migrations (
      id SERIAL PRIMARY KEY,
      filename TEXT UNIQUE NOT NULL,
      executed_at TIMESTAMPTZ DEFAULT NOW()
    );
  `)

    for (const file of files) {
        if (!file.endsWith('.sql')) continue

        const { rows } = await db.query('SELECT * FROM _migrations WHERE filename = $1', [file])

        if (rows.length === 0) {
            console.log(`Executing migration: ${file}`)
            const sql = fs.readFileSync(path.join(migrationsDir, file), 'utf8')

            try {
                await db.query(sql)
                await db.query('INSERT INTO _migrations (filename) VALUES ($1)', [file])
                console.log(`Migration ${file} completed successfully.`)
            } catch (err) {
                console.error(`Error executing migration ${file}:`, err)
                process.exit(1)
            }
        }
    }
}
