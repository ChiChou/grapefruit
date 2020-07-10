// sorry, I don't want to get into any kind of trouble

export function check(bundle: string): boolean {
  if (process.env.NODE_ENV === 'development') {
    return false
  }

  const rules = [
    'com.alibaba.',
    'com.alipay.',
    'com.tencent.',
    'com.ss.'
  ]

  for (const rule of rules) {
    if (bundle.startsWith(rule)) {
      return true
    }
  }

  return false
}
