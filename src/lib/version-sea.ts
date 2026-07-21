const versions: Record<string, string> = {
  frida: process.env.IGF_FRIDA17_VERSION!,
  frida16: process.env.IGF_FRIDA16_VERSION!,
};

export default async function version(pkg: string) {
  const value = versions[pkg];
  if (value) return value;
  throw new Error(`Unknown bundled package: ${pkg}`);
}
