import { inject } from 'vue';
import { SET_TAB_TITLE, RPC } from '@/types';

export function useTabCommons() {
  const tabProps = {
    tabId: String,
    id: Number,
    state: Object,
  }

  const rpc = inject(RPC)!;
  const setTitle = inject(SET_TAB_TITLE)!;

  return {
    rpc,
    tabProps,
    setTitle,
  }
}
