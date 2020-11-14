import { api } from './index'

export default api('Security', {
  SecItemCopyMatching: ['pointer', ['pointer', 'pointer']],
  SecItemDelete: ['pointer', ['pointer']],
  SecAccessControlGetConstraints: ['pointer', ['pointer']],
})
