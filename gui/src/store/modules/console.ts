import { VuexModule, Module, Mutation, Action, getModule } from 'vuex-module-decorators'
import store from '@/store'
import { ContentType, IconType, Level, Log } from '../types'

export interface IConsoleState {
  logs: Log[];
}

@Module({ dynamic: true, store, name: 'app' })
class App extends VuexModule implements IConsoleState {
  public logs: Log[] = []

  @Mutation
  private add(item: Log) {
    item.id = this.logs.length
    if (typeof item.icon === 'undefined') item.icon = IconType.None
    if (typeof item.type === 'undefined') item.type = ContentType.Plain
    if (typeof item.level === 'undefined') item.level = Level.Info
    if (typeof item.time === 'undefined') item.time = new Date().toLocaleString()
    this.logs.push(item)
  }

  @Action
  public log(item: Log) {
    this.add(item)
  }
}

export const ConsoleModule = getModule(App)
