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

// Cookie

export type CookiePredicate = Partial<{
  name: string;
  domain: string;
  path: string;
  isSecure: boolean;
  isHTTPOnly: boolean;
  isSessionOnly: boolean;
}>

export interface Cookie {
  version: number,
  name: string,
  value: string,
  expiresDate: Date,
  domain: string,
  path: string,
  isSecure: boolean,
  isHTTPOnly: boolean,
  portList: number[],
  comment?: string,
  commentURL?: string,
  isSessionOnly: boolean,
  sameSitePolicy?: string,
}

// UI Dump

export type Point = [number, number];
export type Size = [number, number];
export type Frame = [Point, Size];

export interface UIDelegate {
  name?: string;
  description?: string;
}

export interface UIDumpNode {
  clazz: string;
  description?: string;
  children?: UIDumpNode[];
  frame?: Frame;
  preview?: ArrayBuffer;
  delegate?: UIDelegate;
}
