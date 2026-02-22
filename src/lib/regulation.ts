export function check(bundle: string): boolean {
  const rules = process.env.SKIP_BUNDLES?.split(",") || [
    "com.alibaba.",
    "com.alipay.",
    "com.antgroup",
    "com.taobao.",
    "com.alicloud.",
    "com.aliyun.",
    "com.tencent.",
    "com.ss.",
    "com.bytedance",
  ];

  for (const rule of rules)
    if (rule.length && bundle.startsWith(rule)) return true;

  return false;
}
