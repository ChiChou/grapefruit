export type Root = 'bundle' | 'home';

export interface FinderState {
  path: string;
  root: Root;
}

// eslint-disable-next-line no-unused-vars
export enum IconType { In, Out, None }
// eslint-disable-next-line no-unused-vars
export enum ContentType { HTML, Plain }
// eslint-disable-next-line no-unused-vars
export enum Level { Info, Warning, Error }

export interface Log {
  id?: number;
  icon?: IconType;
  type?: ContentType;
  level?: Level;
  time?: string; // use string to avoid parsing from frida agent
  content: string;
  selected?: boolean;
}
