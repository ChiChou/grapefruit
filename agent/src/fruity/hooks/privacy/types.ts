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
  | "focus_status"
  | "game_center"
  | "homekit"
  | "safetykit"
  | "sensorkit";

export interface PrivacyMessage extends BaseMessage {
  subject: "privacy";
  severity: PrivacySeverity;
  category: PrivacyCategory;
}

export const SEVERITY_MAP: Record<PrivacyCategory, PrivacySeverity> = {
  microphone: "critical",
  camera: "critical",
  safetykit: "critical",
  sensorkit: "critical",
  location: "medium",
  health: "medium",
  homekit: "medium",
  photos: "low",
  motion_sensors: "low",
  bluetooth: "low",
  wifi: "low",
  focus_status: "informative",
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
