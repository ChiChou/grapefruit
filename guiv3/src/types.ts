import { Socket } from 'socket.io-client'
import type { InjectionKey, Ref } from 'vue'
import { RPC as WSRPC } from './wsrpc'

// WorkspaceView
export const ACTIVE_SIDEBAR = Symbol('sidebar') as InjectionKey<Ref<number>>
export const DARK = Symbol('dark') as InjectionKey<Ref<boolean>>

export const WS = Symbol('ws') as InjectionKey<Socket>
export const STATUS = Symbol('status') as InjectionKey<Ref<string>>
export const RPC = Symbol('rpc') as InjectionKey<WSRPC>
export const SESSION_DETACH = Symbol('detach') as InjectionKey<() => void>

// Layout
export const SPACE_WIDTH = Symbol('spaceWidth') as InjectionKey<Ref<number>>
export const SPACE_HEIGHT = Symbol('spaceHeight') as InjectionKey<Ref<number>>

export type TabHandler = (name: string, title: string, state: any, newTab?: boolean) => void
export const CREATE_TAB = Symbol('createTab') as InjectionKey<TabHandler>
export const REGISTER_TAB_HANDLER = Symbol('registerTabHandler') as InjectionKey<(handler: TabHandler) => void>