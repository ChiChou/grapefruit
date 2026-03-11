import type {
  MetaData,
  DirectoryListing,
} from "@agent/fruity/modules/fs";

export interface TreeNode {
  meta: MetaData;
  children: TreeNode[] | null;
  isLoading: boolean;
  isExpanded: boolean;
}

export type RootType = "!" | "~";

export interface FinderTabParams {
  path: string;
}

export interface UploadFile {
  name: string;
  progress: number;
  error?: string;
}

export interface LoadDirectoryFn {
  (path: string): Promise<DirectoryListing>;
}

export interface DirectorySelectFn {
  (path: string): void;
}

export function formatSize(size: number | null): string {
  if (size === null) return "-";
  if (size < 1024) return `${size} B`;
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`;
  if (size < 1024 * 1024 * 1024)
    return `${(size / (1024 * 1024)).toFixed(1)} MB`;
  return `${(size / (1024 * 1024 * 1024)).toFixed(1)} GB`;
}

export function formatDate(date: Date): string {
  return new Date(date).toLocaleString();
}

export function typeFor(filename: string): string {
  const ext = filename.split(".").pop()?.toLowerCase();
  if (!ext) return "hex";
  switch (ext) {
    case "txt":
    case "md":
    case "js":
    case "css":
    case "xml":
    case "pem":
    case "json":
    case "ini":
      return "text";

    case "sqlite":
    case "db":
      return "sqlite";

    case "jpeg":
    case "jpg":
    case "png":
    case "gif":
    case "tiff":
    case "tif":
    case "webp":
      return "image";

    case "strings":
    case "loctable":
    case "archiver":
    case "plist":
      return "plist";

    case "xcprivacy":
      return "xcprivacy";

    case "ttf":
    case "otf":
    case "woff":
    case "woff2":
      return "font";

    case "car":
      return "car";

    default:
      return "hex";
  }
}
