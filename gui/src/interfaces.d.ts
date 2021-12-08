
export module Finder {
  export interface Attribute {
    owner: string;
    size: number;
    creation: string;
    permission: number;
    type: string;
    group: string;
    modification: string;
    protection: string;
  }
  
  export interface Item {
    type: 'directory' | 'file';
    name: string;
    path: string;
    attribute: Attribute;
  }
}

