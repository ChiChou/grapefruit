import { api } from './index'

export default api('CoreFoundation', {
  CFStringGetLength: ['long', ['pointer']],
  CFRelease: ['void', ['pointer']],
  CFStringGetCStringPtr: ['pointer', ['pointer', 'uint32']],
  CFGetTypeID: ['pointer', ['pointer']],
  CFBooleanGetTypeID: ['pointer', []],
})
