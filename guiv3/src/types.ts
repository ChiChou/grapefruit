import { Socket } from 'socket.io-client'
import type { InjectionKey, Ref } from 'vue'
import { RPC as WSRPC } from './wsrpc'

export const DARK = Symbol('dark') as InjectionKey<Ref<boolean>>
export const WS = Symbol('ws') as InjectionKey<Socket>
export const STATUS = Symbol('status') as InjectionKey<Ref<string>>
export const RPC = Symbol('rpc') as InjectionKey<WSRPC>