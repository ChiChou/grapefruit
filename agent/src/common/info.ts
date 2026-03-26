export interface ProcessInfo {
  platform: string;
  arch: string;
  pointerSize: number;
  pageSize: number;
}

export function processInfo(): ProcessInfo {
  const { platform, arch, pointerSize, pageSize } = Process;
  return { platform, arch, pointerSize, pageSize };
}
