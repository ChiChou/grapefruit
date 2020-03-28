interface RetryOption {
  retry: number;
  interval: number;
}

export async function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms))
}

export async function retry(operation: Function, opt?: RetryOption): Promise<boolean> {
  if (typeof operation !== 'function') throw new Error('operation should be a function')

  const interval = opt?.interval || 200
  let times = opt?.retry || 10
  while (--times > 0) {
    try {
      return operation()
    } catch (ignored) {
      console.log(ignored)
    }
    await sleep(interval)
  }

  throw new Error('max retry exceed')
}

export function uuidv4(): string {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = Math.random() * 16 | 0, v = c === 'x' ? r : ((r & 0x3) | 0x8)
    return v.toString(16)
  })
}