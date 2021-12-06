import Vue from 'vue'
import Vuex from 'vuex'

import { IFinderState } from './modules/finder'

export interface IRootState {
  finder: IFinderState;
}

Vue.use(Vuex)

export default new Vuex.Store<IRootState>({})
