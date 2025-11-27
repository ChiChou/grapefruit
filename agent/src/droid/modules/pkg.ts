export interface PackageInfo {
  packageName: string;
  versionName: string;
  versionCode: number;
  activities: ActivityInfo[];
  services: ServiceInfo[];
  permissions: string[];
  urlSchemes: UrlSchemeInfo[];
}

export interface ActivityInfo {
  name: string;
  urlSchemes: UrlSchemeInfo[];
}

export interface UrlSchemeInfo {
  schemes: string[];
  browsable: boolean;
  isDefault: boolean;
}

export interface ServiceInfo {
  name: string;
  exported: boolean;
  permission: string | null;
}

export function info() {
  throw new Error("Not implemented");
}
