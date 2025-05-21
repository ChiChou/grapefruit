import ObjC from 'frida-objc-bridge'

let original
let disabled = false

function getClass() {
  if (!Process.findModuleByName('LocalAuthentication'))
    return

  const { LAContext } = ObjC.classes
  if (!LAContext)
    console.error('Warning: touch id is not supported on this device')
  return LAContext
}

export function disable() {
  if (disabled)
    return

  const LAContext = getClass()
  if (!LAContext)
    return

  Interceptor.attach(LAContext['- touchIDAuthenticationAllowableReuseDuration'].implementation, {
    onEnter() {},
    onLeave(retVal) {
      retVal.replace(NULL)
    }
  })

  const method = LAContext['- evaluatePolicy:localizedReason:reply:']
  original = method.implementation
  method.implementation = ObjC.implement(method, (_self, _sel, _policy, _reason, reply) => {
    // send({
    //   subject,
    //   event: 'request',
    //   reason,
    //   date: new Date()
    // })

    // dismiss the dialog
    const callback = new ObjC.Block(ptr(reply))
    callback.implementation(1, null)
  })

  disabled = true
}

export function enable() {
  if (!disabled)
    return
  
  const LAContext = getClass()
  if (!LAContext)
    return
  
  const method = LAContext['- evaluatePolicy:localizedReason:reply:']
  original = method.implementation
  method.implementation = original
  disabled = false
}
