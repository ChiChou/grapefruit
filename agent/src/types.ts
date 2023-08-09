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

