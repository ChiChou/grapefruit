/**
 * This is a frida port of ssl-kill-switch2
 * https://github.com/nabla-c0d3/ssl-kill-switch2/blob/master/SSLKillSwitch/SSLKillSwitch.m
 *
 * Thanks to Alban Diquet and other contributors
 */

const isAbove = (major: number): boolean => 
  ObjC.classes.NSProcessInfo.processInfo().isOperatingSystemAtLeastVersion_([major, 0, 0])
const hooks = new Set<InvocationListener>()
const replacements = new Set<NativePointer>()

const SSL_VERIFY_NONE = NULL
enum ssl_verify_result_t {
  ssl_verify_ok = 0,
  ssl_verify_invalid,
  ssl_verify_retry,
}

const notarealPSKidentity = Memory.allocUtf8String('notarealPSKidentity')
const noValidationCallback = new NativeCallback((ssl: NativePointer, out: NativePointer) => {
  return ssl_verify_result_t.ssl_verify_ok
}, 'int', ['pointer', 'pointer'])
const createPeerTrust = new NativeCallback(() => {
  const errSecSuccess = 0
  return errSecSuccess
}, 'int', ['pointer', 'bool', 'pointer'])

export function enable() {
  if (isAbove(12)) {
    const boringSSL = Module.load('/usr/lib/libboringssl.dylib')
    const SSL_set_custom_verify = boringSSL.findExportByName('SSL_set_custom_verify')
    if (SSL_set_custom_verify) {
      console.log('hooking boringssl!SSL_set_custom_verify')
      hooks.add(
        Interceptor.attach(SSL_set_custom_verify, {
          onEnter(args) {
            console.log('patch SSL_CTX_set_custom_verify')
            args[1] = SSL_VERIFY_NONE
            args[2] = noValidationCallback
          }
        })
      )
    }

    const SSL_CTX_set_custom_verify = boringSSL.findExportByName('SSL_CTX_set_custom_verify')
    if (SSL_CTX_set_custom_verify) {
      console.log('hooking boringssl!SSL_CTX_set_custom_verify')
      hooks.add(
        Interceptor.attach(SSL_CTX_set_custom_verify, {
          onEnter(args) {
            console.log('patch SSL_CTX_set_custom_verify')
            args[1] = SSL_VERIFY_NONE
            args[2] = noValidationCallback
          }
        })
      )
    }

    const SSL_get_psk_identity = boringSSL.findExportByName('SSL_get_psk_identity')
    if (SSL_get_psk_identity) {
      console.log('hooking boringssl!SSL_get_psk_identity')
      hooks.add(Interceptor.attach(SSL_get_psk_identity, { onLeave: () => notarealPSKidentity }))
    }
  } else if (isAbove(11)) {
    const libnetwork = Module.load('/usr/lib/libnetwork.dylib')
    const p = libnetwork.findExportByName('nw_tls_create_peer_trust')
    if (p) {
      replacements.add(p)
      Interceptor.replace(p, createPeerTrust)
    }
  } else if (isAbove(10)) {
    const p = Module.findExportByName(null, 'tls_helper_create_peer_trust')
    if (p) {
      replacements.add(p)
      Interceptor.replace(p, createPeerTrust)
    }
  } else if (isAbove(8)) {
    // do nothing. see below
  } else {
    console.warn('Seemed like you are below iOS 8. This system may not be supported')
  }

  const { SPDYProtocol } = ObjC.classes
  if (SPDYProtocol) {
    const setTrustEvaluator = SPDYProtocol['- setTLSTrustEvaluator:']
    if (setTrustEvaluator) {
      hooks.add(
        Interceptor.attach(setTrustEvaluator.implementation, {
          onEnter(args) {
            args[2] = NULL
          }
        })
      )
    }

    for (const m of ['- registerOrigin:', '- setprotocolClasses:']) {
      const method = SPDYProtocol[m]
      if (!method) continue
      replacements.add(method.implementation)
      Interceptor.replace(method.implementation, ObjC.implement(method, (self, sel, ...args) => {
        // do nothing
      }))
    }
  }

  // above iOS8
  const prototypes: { [key: string]: [string, string[]] } = {
    SSLHandshake: ['int', ['pointer']],
    SSLSetSessionOption: ['int', ['pointer', 'int', 'bool']]
  }

  const kSSLSessionOptionBreakOnServerAuth = 0
  const noErr = 0
  const originalFunctions: { [key: string]: NativeFunction } = {}

  for (const [name, proto] of Object.entries(prototypes)) {
    const p = Module.findExportByName('Security', name)
    if (!p) continue
    const [retType, argTypes] = proto
    const original = new NativeFunction(p, retType, argTypes)
    const callbacks: { [key: string]: NativeCallbackImplementation } = {
      SSLHandshake(context: NativePointer) {
        const errSSLServerAuthCompared = -9481
        const status = original(context)
        if (status == errSSLServerAuthCompared) {
          console.log('SSLHandshake got called, skip certificate validation')
          return original(context)
        }
        return status
      },
      SSLSetSessionOption(context: NativePointer, opt: number, val: boolean) {
        if (opt === kSSLSessionOptionBreakOnServerAuth) return noErr
        return original(context, opt, val)
      }
    }
    const cb = callbacks[name]
    replacements.add(p)
    Interceptor.replace(p, new NativeCallback(cb, retType, argTypes))
  }

  const SSLCreateContext = Module.findExportByName('Security', 'SSLCreateContext')
  if (SSLCreateContext) {
    hooks.add(
      Interceptor.attach(SSLCreateContext, {
        onLeave(retVal) {
          const context = retVal
          const { SSLSetSessionOption } = originalFunctions
          SSLSetSessionOption(context, kSSLSessionOptionBreakOnServerAuth, 1)
        }
      })
    )
  }

}

export function disable() {
  for (const h of hooks) h.detach()
  for (const p of replacements) Interceptor.revert(p)
}
