import { VuexModule, Module, Mutation, Action, getModule } from 'vuex-module-decorators'
import store from '@/store'
import { Root } from '../types'

export interface IFinderState {
  root: Root;
  path: string;
}

@Module({ dynamic: true, store, name: 'app' })
class App extends VuexModule implements IFinderState {
  public root: Root = 'home'
  public path = ''

  @Mutation
  private goto(path: string) {
    const tail = path.substring(2)
    if (path === '~' || path.startsWith('~/')) {
      this.root = 'home'
    } else if (path === '!' || path.startsWith('!/')) {
      this.root = 'bundle'
    } else {
      throw new Error('invalid path: ' + path)
    }
    this.path = tail
  }

  @Mutation
  public changeDir(path: string) {
    this.path = path
  }

  @Action
  public cd(path: string) {
    this.changeDir(path)
  }

  @Action
  public goTmp() {
    this.goto('~/tmp')
  }

  @Action
  public goHome() {
    this.goto('~')
  }

  @Action
  public goApp() {
    this.goto('!')
  }
}

export const FinderModule = getModule(App)
