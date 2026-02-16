let passed = 0;
let failed = 0;
let skipped = 0;
const errors: string[] = [];

export function json(obj: unknown, indent = 2) {
  return JSON.stringify(obj, null, indent);
}

export async function test(name: string, fn: () => Promise<void>) {
  try {
    await fn();
    passed++;
    console.log(`  PASS  ${name}`);
  } catch (e) {
    failed++;
    const msg = e instanceof Error ? e.message : String(e);
    errors.push(`${name}: ${msg}`);
    console.log(`  FAIL  ${name} - ${msg}`);
  }
}

export function skip(name: string, reason: string) {
  skipped++;
  console.log(`  SKIP  ${name} - ${reason}`);
}

export function assert(cond: boolean, msg: string) {
  if (!cond) throw new Error(`assertion failed: ${msg}`);
}

export function assertType(value: unknown, type: string, label: string) {
  assert(
    typeof value === type,
    `${label}: expected ${type}, got ${typeof value}`,
  );
}

export function assertArray(
  value: unknown,
  label: string,
): asserts value is unknown[] {
  assert(Array.isArray(value), `${label}: expected array`);
}

export function assertKeys(
  obj: Record<string, unknown>,
  keys: string[],
  label: string,
) {
  for (const k of keys) {
    assert(k in obj, `${label}: missing key "${k}"`);
  }
}

export function assertNonEmpty(arr: unknown[], label: string) {
  assert(arr.length > 0, `${label}: expected non-empty array`);
}

export function summary() {
  console.log("\n=== summary ===");
  console.log(`  ${passed} passed, ${failed} failed, ${skipped} skipped`);

  if (errors.length > 0) {
    console.log("\nfailures:");
    for (const e of errors) {
      console.log(`  - ${e}`);
    }
  }
}
