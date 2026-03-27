import { parse } from "yaml";

// Imported as raw strings via webpack/turbopack asset rules

import enRaw from "./en.yaml";

import zhRaw from "./zh.yaml";

export const en: Record<string, string> = parse(enRaw);
export const zh: Record<string, string> = parse(zhRaw);
