export interface URLScheme {
  name: string;
  schemes: string[];
  role: string;
}

export interface BasicInfo {
  tmp: string;
  home: string;
  id: string;
  label: string;
  path: string;
  main: string;
  version: string;
  semVer: string;
  minOS: string;
  urls: URLScheme[];
}

export interface Entitlements {
  [key: string]: string | boolean | number | string[];
}

export interface CheckSecFlags {
  pie: boolean;
  arc: boolean;
  canary: boolean;
  encrypted: boolean;
}
