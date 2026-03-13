import type { BaseMessage } from "@/common/hooks/context.js";

export type PrivacySeverity = "informative" | "low" | "medium" | "critical";

export type PrivacyCategory =
  | "microphone"
  | "camera"
  | "location"
  | "health"
  | "photos"
  | "motion_sensors"
  | "bluetooth"
  | "wifi"
  | "game_center"
  | "homekit"
  | "activity_recognition"
  | "usage_stats";

export interface PrivacyMessage extends BaseMessage {
  subject: "privacy";
  severity: PrivacySeverity;
  category: PrivacyCategory;
}

export const SEVERITY_MAP: Record<PrivacyCategory, PrivacySeverity> = {
  microphone: "critical",
  camera: "critical",
  location: "medium",
  health: "medium",
  usage_stats: "medium",
  activity_recognition: "medium",
  homekit: "medium",
  photos: "low",
  motion_sensors: "low",
  bluetooth: "low",
  wifi: "low",
  game_center: "informative",
};

export function privacyMsg(
  category: PrivacyCategory,
  symbol: string,
  dir: "enter" | "leave",
  line?: string,
  backtrace?: string[],
  extra?: Record<string, unknown>,
): PrivacyMessage {
  return {
    subject: "privacy",
    category,
    severity: SEVERITY_MAP[category],
    symbol,
    dir,
    line,
    backtrace,
    extra,
  };
}
