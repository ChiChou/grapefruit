import { Readable } from 'stream'

interface Task {
  stream: Readable;
  name: string;
  size: number;
}

export const registry = new Map<string, Task>()
