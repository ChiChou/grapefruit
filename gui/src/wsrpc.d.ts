import Vue from 'vue'

export type RPC = {
  [key: string]: RPC;
  (...args: any): any;
}

declare module 'vue/types/vue' {
  interface Vue {
    $rpc: RPC;
    rpcReady(): Promise<boolean>;
    ws(event: string, ...args: any): Promise<any>;
  }
}

declare module "*.json" {
  const value: any;
  export default value;
}