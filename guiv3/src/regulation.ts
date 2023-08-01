// sorry, I don't want to get into any kind of trouble

export function check(bundle: string): boolean {
  if (import.meta.env.DEV) {
    return false
  }

  const regex = /^com\.(alibaba|alipay|tencent|ss)\./;
  return regex.test(bundle);
}
