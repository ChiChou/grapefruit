import { type ReactNode, useCallback, useEffect, useState } from "react";
import { useR2, type Platform, type Architecture } from "@frida/react-use-r2";
import { useSession, Status } from "@/context/SessionContext";

interface ProcessInfo {
  platform: string;
  arch: string;
  pointerSize: number;
  pageSize: number;
}

function mapPlatform(platform: string): Platform {
  const platformMap: Record<string, Platform> = {
    darwin: "darwin",
    linux: "linux",
    windows: "windows",
  };
  return platformMap[platform] ?? "darwin";
}

function mapArch(arch: string): Architecture {
  const archMap: Record<string, Architecture> = {
    arm: "arm",
    ia32: "ia32",
    x86: "ia32",
    x64: "x64",
  };
  return archMap[arch] ?? "arm64";
}

export function R2Provider({ children }: { children: ReactNode }) {
  const { fruity, status } = useSession();
  const [processInfo, setProcessInfo] = useState<ProcessInfo | null>(null);

  useEffect(() => {
    if (status !== Status.Ready || !fruity) {
      setProcessInfo(null);
      return;
    }

    fruity.info.processInfo().then(setProcessInfo).catch(console.error);
  }, [fruity, status]);

  const onReadRequest = useCallback(
    async (address: bigint, size: number): Promise<Uint8Array | null> => {
      if (!fruity) return null;

      // Agent's memory.dump has a 2KB limit, so we need to chunk reads
      const CHUNK_SIZE = 2048;
      const result = new Uint8Array(size);
      let offset = 0;

      while (offset < size) {
        const chunkSize = Math.min(CHUNK_SIZE, size - offset);
        const chunkAddress = address + BigInt(offset);
        try {
          const chunk = await fruity.memory.dump(
            "0x" + chunkAddress.toString(16),
            chunkSize,
          );
          if (chunk === null) {
            // Read failed - fill remaining with zeros
            return null;
          }
          result.set(new Uint8Array(chunk), offset);
          offset += chunk.byteLength;
          // If we got less than requested, stop
          if (chunk.byteLength < chunkSize) {
            break;
          }
        } catch {
          return null;
        }
      }

      return result;
    },
    [fruity],
  );

  useR2({
    source:
      processInfo !== null
        ? {
            platform: mapPlatform(processInfo.platform),
            arch: mapArch(processInfo.arch),
            pointerSize: processInfo.pointerSize,
            pageSize: processInfo.pageSize,
            onReadRequest,
          }
        : undefined,
  });

  return <>{children}</>;
}
