import { Readable } from 'stream'

interface Task {
  stream: Readable;
  done: boolean;
  name: string;
  size: number;
}

const registry = new Map<string, Task>()

export function begin(session: string, size: number, path: string): void {
  const stream = new Readable({
    read(): void {
      // empty
    }
  })
  const name = path.split('/').pop()
  const task = { stream, size, name, done: false }
  registry.set(session, task)
}

export function get(session: string): Task {
  if (!registry.has(session)) throw new Error(`session "${session} not found`)
  return registry.get(session)
}

export function push(session: string, data: Buffer): void {
  get(session).stream.push(data)
}

export function end(session: string): void {
  const task = get(session)
  task.stream.push(null)
  task.done = true 
}

export function request(session: string): Task {
  const task = get(session)
  const cleanup = (): void => {  
    task.stream.destroy()
    registry.delete(session)
  }

  if (task.done) {
    cleanup()
  } else {
    task.stream.on('end', cleanup)
  }

  return task
}
