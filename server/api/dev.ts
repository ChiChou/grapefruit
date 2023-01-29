export interface App {
  identifier: string;
  name: string;
}

export interface Info {
  name?: string;
  arch?: string;
  os: {
    version?: string;
  };
  platform?: string;
  access?: string;
}
