import { Socket } from 'socket.io-client'
import type { InjectionKey, Ref } from 'vue'
import { RPC as WSRPC } from './wsrpc'
import tabMgr from '@/plugins/tab-manager'

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

// tab manager
export const TAB_EMITTER = Symbol('tabEmitter') as InjectionKey<typeof tabMgr>
export const SET_TAB_TITLE = Symbol('setTabTitle') as InjectionKey<(id: string, title: string) => void>