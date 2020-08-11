import { Event } from '../models/Event'
import { Tag } from '../models/Tag'
import { Snippet } from '../models/Snippet'
import { concat } from './workspace'
import { createConnection, Connection, ConnectionOptions } from 'typeorm'

export const config: ConnectionOptions = {
  type: 'sqlite',
  database: concat('grapefruit.db'),
  entities: [Event, Snippet, Tag],
  logging: true
}

export async function connect(): Promise<Connection> {
  return createConnection(config)
}

export function env(): { [key: string]: string } {
  const result: { [key: string]: string } = {
    TYPEORM_MIGRATIONS: 'migrations/*.ts',
    TYPEORM_MIGRATIONS_DIR: 'migrations'
  }

  for (const [key, value] of Object.entries(config)) {
    let newKey = `TYPEORM_${key.toUpperCase()}`
    if (key === 'entities') {
      result[newKey] = 'models/*.ts'
    } else {
      if (key === 'type') {
        newKey = 'TYPEORM_CONNECTION'
      }
      result[newKey] = value.toString()
    }
  }
  return result;
}