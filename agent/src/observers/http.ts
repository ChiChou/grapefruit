/*
 * thanks to 
 * https://github.com/FLEXTool/FLEX
 * https://github.com/ProxymanApp/atlantis
 */

const subject = 'http'

const OBJC_ASSOCIATION_RETAIN_NONATOMIC = 1
const key = Memory.allocUtf8String('me.chichou.grapefruit/requestId')
const objc_getAssociatedObject = new NativeFunction(
  Module.findExportByName(null, 'objc_getAssociatedObject') as NativePointer,
  'pointer', ['pointer', 'pointer'])
const objc_setAssociatedObject = new NativeFunction(
  Module.findExportByName(null, 'objc_setAssociatedObject') as NativePointer,
  'void', ['pointer', 'pointer', 'pointer', 'ulong'])

function setid(id: ObjC.Object, task: NativePointer) {
  objc_setAssociatedObject(
    task,
    key,
    id,
    OBJC_ASSOCIATION_RETAIN_NONATOMIC)
}

function headers(allHeaders: ObjC.Object) {
  const keys = allHeaders.allKeys()
  const buf = []
  for (let i = 0; i < keys.count(); i++) {
    const key = keys.objectAtIndex_(i)
    buf.push(`${key}: ${allHeaders.objectForKey_(key)}`)
  }
  return buf.join('\n')
}

function reqid(task: NativePointer) {
  const id = objc_getAssociatedObject(task, key) as NativePointer
  if (id.isNull()) {
    const newId = ObjC.classes.NSUUID.UUID().UUIDString()
    setid(newId, task)
    return newId
  }
  return new ObjC.Object(id).toString()
}

const avaliable = (() => {
  let cached: number = NaN
  return (expected: number) => {
    if (Number.isNaN(cached))
      cached = ObjC.classes.UIDevice.currentDevice().systemVersion().intValue()
    return cached > expected
  }
})()

function hook(clazz: ObjC.Object, sel: string, cb: InvocationListenerCallbacks) {
  const method = clazz[sel]
  if (!method) {
    console.warn(`method ${sel} not found in class ${clazz}`)
    return
  }
  const { implementation } = method as ObjC.ObjectMethod
  return Interceptor.attach(implementation, cb)
}

function injectIntoURLSessionDelegate(clazz: ObjC.Object) {
  const selector = avaliable(13) ? '- _didReceiveResponse:sniff:rewrite:' : '- _didReceiveResponse:sniff:'
  hook(clazz, selector, {
    onEnter(args) {
      console.log('response:', new ObjC.Object(args[2]))
    }
  })

  hook(clazz, '- _didReceiveData:', {
    onEnter(args) {
      console.log('data:', new ObjC.Object(args[2]))
    }
  })

  hook(clazz, '- _didFinishWithError:', {
    onEnter(args) {
      console.log('data:', new ObjC.Object(args[2]))
    }
  })
}

function injectURLConnectionDelegate(clazz: ObjC.Object) {
  // _swizzleConnectionDidReceiveResponse
  hook(clazz, '- connection:didReceiveResponse:', {
    onEnter(args) {
      console.log('receive response', new ObjC.Object(args[3]))
    }
  })

  hook(clazz, '- connection:didReceiveData:', {
    onEnter(args) {
      console.log('receive data', new ObjC.Object(args[3]))
    }
  })

  hook(clazz, '- connection:didFailWithError:', {
    onEnter(args) {
      console.log('connection:didFailWithError:', new ObjC.Object(args[3]))
    }
  })
}

function injectAllURLSession() {
  const clazz = ObjC.classes.__NSCFURLLocalSessionConnection || ObjC.classes.__NSCFURLSessionConnection
  if (!clazz) throw new Error('failed to hook NSURLSession. Unsupported iOS')
  injectIntoURLSessionDelegate(clazz)
}

function injectAllURLConnection() {
  const r = new ApiResolver('objc')
  for (const method of r.enumerateMatches('-[* connection:didReceiveResponse:]')) {
    const name = method.name.slice('-['.length, method.name.indexOf(' '))
    const clazz = ObjC.classes[name]

    if ('NSURLConnectionDataDelegate' in clazz.$protocols || 'NSURLConnectionDelegate' in clazz.$protocols) {
      injectURLConnectionDelegate(clazz)
    }
  }
}

function injectURLSessionResume() {
  // In iOS 7 resume lives in __NSCFLocalSessionTask
  // In iOS 8 resume lives in NSURLSessionTask
  // In iOS 9 resume lives in __NSCFURLSessionTask
  // In iOS 14 resume lives in NSURLSessionTask
  
  let clazz: ObjC.Object
  const info = ObjC.classes.NSProcessInfo.processInfo()
  if (typeof info.operatingSystemVersion !== 'function') {
    clazz = ObjC.classes.__NSCFLocalSessionTask
  } else {
    const major = +(info.operatingSystemVersion()[0] as string)
    if (major < 9 || major >= 14) {
      clazz = ObjC.classes.NSURLSessionTask
    } else {
      clazz = ObjC.classes.__NSCFURLSessionTask
    }
  }

  if (!clazz)
    throw new Error('Unable to find URLSession class, your iOS may not be supported')

  hook(clazz, '- resume', {
    onEnter(args) {
      console.log('resume', new ObjC.Object(args[0]).currentRequest())
    }
  })
}

function injectURLSessionUploadTasks() {
  const clazz = ObjC.classes.NSURLSession
  hook(clazz, '- uploadTaskWithRequest:fromFile:', {
    onEnter(args) {

    }
  })

  hook(clazz, '- uploadTaskWithRequest:fromFile:completionHandler:', {
    onEnter(args) {

    }
  })

  hook(clazz, '- uploadTaskWithRequest:fromData:', {
    onEnter(args) {

    }
  })

  hook(clazz, '- uploadTaskWithRequest:fromData:completionHandler:', {
    onEnter(args) {

    }
  })
}

function injectURLSessionWebsocketTasks() {
  const clazz = ObjC.classes.__NSURLSessionWebSocketTask
  if (!clazz) return
  
  hook(clazz, '- sendMessage:completionHandler:', {
    onEnter(args) {

    }
  })

  hook(clazz, '- receiveMessageWithCompletionHandler:', {
    onEnter(args) {

    }
  })

  hook(clazz, '- sendPingWithPongReceiveHandler:', {
    onEnter(args) {

    }
  })

  hook(clazz, '- cancelWithCloseCode:reason:', {
    onEnter(args) {

    }
  })
}

export function init() {
  injectAllURLSession()
  injectAllURLConnection()
  injectURLSessionResume()
  injectURLSessionUploadTasks()
  injectURLSessionWebsocketTasks()
}
