import { type ReactNode, useCallback } from "react";
import { useR2, type Platform, type Architecture } from "@/lib/use-r2";
import { useSession } from "@/context/SessionContext";
import { usePlatformQuery } from "@/lib/queries";

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
  const { fruity, droid, platform } = useSession();

  const { data: processInfo } = usePlatformQuery<ProcessInfo>(
    ["processInfo"],
    (api) => api.info.processInfo(),
  );

  const rpc = platform === "droid" ? droid : fruity;

  const onReadRequest = useCallback(
    async (address: bigint, size: number): Promise<Uint8Array | null> => {
      if (!rpc) return null;

      const CHUNK_SIZE = 2048;
      const result = new Uint8Array(size);
      let offset = 0;

      while (offset < size) {
        const chunkSize = Math.min(CHUNK_SIZE, size - offset);
        const chunkAddress = address + BigInt(offset);
        try {
          const chunk = await rpc.memory.dump(
            "0x" + chunkAddress.toString(16),
            chunkSize,
          );
          if (chunk === null) return null;
          const bytes = new Uint8Array(chunk);
          result.set(bytes, offset);
          offset += bytes.byteLength;
          if (bytes.byteLength < chunkSize) break;
        } catch {
          return null;
        }
      }

      return result;
    },
    [rpc],
  );

  useR2({
    source: processInfo
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
