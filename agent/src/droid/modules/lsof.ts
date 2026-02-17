import { getGlobalExport } from "@/lib/polyfill.js";

// ---------------------------------------------------------------------------
// types
// ---------------------------------------------------------------------------

export enum FDType {
  TCP = "tcp",
  TCP6 = "tcp6",
  UDP = "udp",
  UDP6 = "udp6",
  FILE = "file",
}

export interface TcpEntry {
  fd: number | null;
  type: FDType.TCP | FDType.TCP6;
  localIp: string;
  localPort: number;
  remoteIp: string;
  remotePort: number;
  state: string;
  inode: number;
}

export interface UdpEntry {
  fd: number | null;
  type: FDType.UDP | FDType.UDP6;
  localIp: string;
  localPort: number;
  remoteIp: string;
  remotePort: number;
  inode: number;
}

export interface FileEntry {
  fd: number;
  type: FDType.FILE;
  path: string;
}

export type FileDescriptor = TcpEntry | UdpEntry | FileEntry;

// ---------------------------------------------------------------------------
// native helpers
// ---------------------------------------------------------------------------

const open = new NativeFunction(getGlobalExport("open"), "int", [
  "pointer",
  "int",
  "int",
]);
const read = new NativeFunction(getGlobalExport("read"), "int", [
  "int",
  "pointer",
  "int",
]);
const close = new NativeFunction(getGlobalExport("close"), "int", ["int"]);
const readlink = new NativeFunction(getGlobalExport("readlink"), "int", [
  "pointer",
  "pointer",
  "int",
]);
const opendir = new NativeFunction(getGlobalExport("opendir"), "pointer", [
  "pointer",
]);
const readdir = new NativeFunction(getGlobalExport("readdir"), "pointer", [
  "pointer",
]);
const closedir = new NativeFunction(getGlobalExport("closedir"), "int", [
  "pointer",
]);

// ---------------------------------------------------------------------------
// proc helpers
// ---------------------------------------------------------------------------

/** Read a proc file via chunked reads (proc files report size 0). */
function readProcFile(path: string): string {
  const pathBuf = Memory.allocUtf8String(path);
  const fd = open(pathBuf, 0 /* O_RDONLY */, 0) as number;
  if (fd < 0) return "";

  const chunkSize = 4096;
  const buf = Memory.alloc(chunkSize);
  let result = "";

  // eslint-disable-next-line no-constant-condition
  while (true) {
    const n = read(fd, buf, chunkSize) as number;
    if (n <= 0) break;
    result += buf.readUtf8String(n);
  }

  close(fd);
  return result;
}

/** Resolve a symlink path using native readlink. */
function resolveLink(path: string): string | null {
  const pathBuf = Memory.allocUtf8String(path);
  const buf = Memory.alloc(4096);
  const n = readlink(pathBuf, buf, 4096) as number;
  if (n < 0) return null;
  return buf.readUtf8String(n);
}

// ---------------------------------------------------------------------------
// TCP state mapping
// ---------------------------------------------------------------------------

const TCP_STATES: Record<string, string> = {
  "01": "ESTABLISHED",
  "02": "SYN_SENT",
  "03": "SYN_RECV",
  "04": "FIN_WAIT1",
  "05": "FIN_WAIT2",
  "06": "TIME_WAIT",
  "07": "CLOSE",
  "08": "CLOSE_WAIT",
  "09": "LAST_ACK",
  "0A": "LISTEN",
  "0B": "CLOSING",
};

// ---------------------------------------------------------------------------
// IP address parsing
// ---------------------------------------------------------------------------

/** Parse a hex-encoded IPv4 address (little-endian 32-bit). */
function parseIPv4(hex: string): string {
  const n = parseInt(hex, 16);
  return [n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >> 24) & 0xff].join(
    ".",
  );
}

/** Parse a hex-encoded IPv6 address (4 little-endian 32-bit words). */
function parseIPv6(hex: string): string {
  // hex is 32 chars = 4 groups of 8 chars, each a LE 32-bit word
  const words: number[] = [];
  for (let i = 0; i < 32; i += 8) {
    words.push(parseInt(hex.substring(i, i + 8), 16));
  }

  // Convert each 32-bit LE word to two 16-bit network-order groups
  const groups: string[] = [];
  for (const w of words) {
    groups.push(((w & 0xff) << 8 | (w >> 8) & 0xff).toString(16));
    groups.push(((w >> 16 & 0xff) << 8 | (w >> 24) & 0xff).toString(16));
  }

  const full = groups.join(":");

  // Collapse longest run of :0: groups
  // Simple approach: just return the joined form
  return compressIPv6(full);
}

function compressIPv6(addr: string): string {
  const parts = addr.split(":");
  // Find the longest run of "0" groups
  let bestStart = -1;
  let bestLen = 0;
  let curStart = -1;
  let curLen = 0;

  for (let i = 0; i < parts.length; i++) {
    if (parts[i] === "0") {
      if (curStart === -1) curStart = i;
      curLen++;
      if (curLen > bestLen) {
        bestStart = curStart;
        bestLen = curLen;
      }
    } else {
      curStart = -1;
      curLen = 0;
    }
  }

  if (bestLen >= 2) {
    const before = parts.slice(0, bestStart);
    const after = parts.slice(bestStart + bestLen);
    const mid = bestStart === 0 && bestStart + bestLen === parts.length
      ? "::"
      : bestStart === 0
        ? "::" + after.join(":")
        : bestStart + bestLen === parts.length
          ? before.join(":") + "::"
          : before.join(":") + "::" + after.join(":");
    return mid;
  }

  return addr;
}

// ---------------------------------------------------------------------------
// /proc/self/net parsing
// ---------------------------------------------------------------------------

interface NetEntry {
  localIp: string;
  localPort: number;
  remoteIp: string;
  remotePort: number;
  state: string;
  inode: number;
}

function parseNetFile(content: string, isV6: boolean): NetEntry[] {
  const entries: NetEntry[] = [];
  const lines = content.split("\n");

  // Skip header line
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line) continue;

    //  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
    const fields = line.split(/\s+/);
    if (fields.length < 10) continue;

    const [localHex, localPortHex] = fields[1].split(":");
    const [remoteHex, remotePortHex] = fields[2].split(":");

    const parseIp = isV6 ? parseIPv6 : parseIPv4;

    entries.push({
      localIp: parseIp(localHex),
      localPort: parseInt(localPortHex, 16),
      remoteIp: parseIp(remoteHex),
      remotePort: parseInt(remotePortHex, 16),
      state: fields[3],
      inode: parseInt(fields[9], 10),
    });
  }

  return entries;
}

// ---------------------------------------------------------------------------
// /proc/self/fd listing
// ---------------------------------------------------------------------------

/** d_name offset: 19 on 64-bit, 11 on 32-bit */
const DIRENT_D_NAME_OFFSET = Process.pointerSize === 8 ? 19 : 11;

interface FdLink {
  fd: number;
  target: string;
}

function listFds(): FdLink[] {
  const dirPath = Memory.allocUtf8String("/proc/self/fd");
  const dir = opendir(dirPath) as NativePointer;
  if (dir.isNull()) return [];

  const results: FdLink[] = [];

  // eslint-disable-next-line no-constant-condition
  while (true) {
    const entry = readdir(dir) as NativePointer;
    if (entry.isNull()) break;

    const name = entry.add(DIRENT_D_NAME_OFFSET).readUtf8String();
    if (!name || name === "." || name === "..") continue;

    const fdNum = parseInt(name, 10);
    if (isNaN(fdNum)) continue;

    const target = resolveLink(`/proc/self/fd/${name}`);
    if (target) {
      results.push({ fd: fdNum, target });
    }
  }

  closedir(dir);
  return results;
}

// ---------------------------------------------------------------------------
// main export
// ---------------------------------------------------------------------------

export function fds(): FileDescriptor[] {
  // 1. Parse net files
  const tcpContent = readProcFile("/proc/self/net/tcp");
  const tcp6Content = readProcFile("/proc/self/net/tcp6");
  const udpContent = readProcFile("/proc/self/net/udp");
  const udp6Content = readProcFile("/proc/self/net/udp6");

  const tcpEntries = parseNetFile(tcpContent, false);
  const tcp6Entries = parseNetFile(tcp6Content, true);
  const udpEntries = parseNetFile(udpContent, false);
  const udp6Entries = parseNetFile(udp6Content, true);

  // 2. Build inode -> net entry map
  const inodeMap = new Map<number, { entry: NetEntry; type: FDType }>();
  for (const e of tcpEntries) inodeMap.set(e.inode, { entry: e, type: FDType.TCP });
  for (const e of tcp6Entries) inodeMap.set(e.inode, { entry: e, type: FDType.TCP6 });
  for (const e of udpEntries) inodeMap.set(e.inode, { entry: e, type: FDType.UDP });
  for (const e of udp6Entries) inodeMap.set(e.inode, { entry: e, type: FDType.UDP6 });

  // 3. List fds and correlate
  const fdLinks = listFds();
  const results: FileDescriptor[] = [];
  const matchedInodes = new Set<number>();

  for (const { fd, target } of fdLinks) {
    // Check for socket:[inode]
    const socketMatch = target.match(/^socket:\[(\d+)\]$/);
    if (socketMatch) {
      const inode = parseInt(socketMatch[1], 10);
      const net = inodeMap.get(inode);
      if (net) {
        matchedInodes.add(inode);
        const { entry, type } = net;
        if (type === FDType.TCP || type === FDType.TCP6) {
          results.push({
            fd,
            type,
            localIp: entry.localIp,
            localPort: entry.localPort,
            remoteIp: entry.remoteIp,
            remotePort: entry.remotePort,
            state: TCP_STATES[entry.state] || entry.state,
            inode,
          });
        } else {
          results.push({
            fd,
            type: type as FDType.UDP | FDType.UDP6,
            localIp: entry.localIp,
            localPort: entry.localPort,
            remoteIp: entry.remoteIp,
            remotePort: entry.remotePort,
            inode,
          });
        }
      }
      // Skip unmatched sockets (no net entry found)
      continue;
    }

    // Regular file
    results.push({
      fd,
      type: FDType.FILE,
      path: target,
    });
  }

  // 4. Add unmatched net entries (sockets without an fd in our process)
  for (const [inode, { entry, type }] of inodeMap) {
    if (matchedInodes.has(inode)) continue;
    if (type === FDType.TCP || type === FDType.TCP6) {
      results.push({
        fd: null,
        type,
        localIp: entry.localIp,
        localPort: entry.localPort,
        remoteIp: entry.remoteIp,
        remotePort: entry.remotePort,
        state: TCP_STATES[entry.state] || entry.state,
        inode,
      });
    } else {
      results.push({
        fd: null,
        type: type as FDType.UDP | FDType.UDP6,
        localIp: entry.localIp,
        localPort: entry.localPort,
        remoteIp: entry.remoteIp,
        remotePort: entry.remotePort,
        inode,
      });
    }
  }

  return results;
}
