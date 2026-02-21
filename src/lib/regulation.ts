export function check(bundle: string): boolean {
  const rules = process.env.SKIP_BUNDLES?.split(",") || [
    "com.alibaba.",
    "com.alipay.",
    "com.taobao.",
    "com.tencent.",
    "com.ss.",
  ];

  for (const rule of rules)
    if (rule.length && bundle.startsWith(rule)) return true;

  return false;
}
