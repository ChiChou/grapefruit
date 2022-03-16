import { VuexModule, Module, Mutation, Action, getModule } from 'vuex-module-decorators'
import store from '@/store'
import { ContentType, IconType, Level, Log } from '../types'

export interface IConsoleState {
  logs: Log[];
}

@Module({ dynamic: true, store, name: 'app' })
class App extends VuexModule implements IConsoleState {
  public logs: Log[] = []

  public limit = 100

  @Mutation
  private add(item: Log) {
    item.id = this.logs.length
    if (typeof item.icon === 'undefined') item.icon = IconType.None
    if (typeof item.type === 'undefined') item.type = ContentType.Plain
    if (typeof item.level === 'undefined') item.level = Level.Info
    if (typeof item.time === 'undefined') item.time = new Date().toLocaleString()
    this.logs.push(item)

    if (this.logs.length > this.limit) {
      this.logs.shift()
    }
  }

  @Mutation
  private setMaxItems(limit: number) {
    this.limit = limit
    if (this.logs.length > this.limit) {
      this.logs.splice(0, this.logs.length - this.limit)
    }
  }

  @Mutation
  private doClear() {
    this.logs = []
  }

  @Action
  public clear() {
    this.doClear()
  }

  @Action
  public log(item: Log) {
    this.add(item)
  }

  @Action
  public setLimit(limit: number) {
    this.setMaxItems(limit)
  }
}

export const ConsoleModule = getModule(App)
