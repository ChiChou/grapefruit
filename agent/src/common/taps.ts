export interface TapInfo {
  id: string;
  active: boolean;
  available: boolean;
}

export type TapRule =
  | { type: "builtin"; id: string }
  | { type: "objc"; cls: string; sel: string }
  | {
      type: "native";
      module: string | null;
      name: string;
      sig?: { args: string[]; returns: string };
    };

