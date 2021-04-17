type Hook = ScriptInvocationListenerCallbacks
type Handler = { [sel: string]: Hook }

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

const dataTaskHookHandler: Hook = {
  onEnter(args) {
    if (args[3]) {
      this.completionHandler = new ObjC.Block(args[3])
    }
  },
  onLeave(retVal) {
    const { completionHandler } = this
    if (completionHandler) {
      reqid(retVal)

      const task = new ObjC.Object(retVal)
      const req = task.currentRequest()

      console.log('>', req.HTTPMethod(), req.URL())
      const body = req.HTTPBody()
      console.log(headers(req.allHTTPHeaderFields()))
      if (body)
        console.log(body)

      const originalCallback = completionHandler.implementation
      completionHandler.implementation = (...args: any) => {
        console.log('finish', this.method)
        originalCallback(...args)
      }
    }
  }
}

const uploadTaskHookHandler: Hook = {
  onEnter(args) {

  }
}

const handlers: Handler = {
  // https://github.com/Flipboard/FLEX/blob/b38cca06b/Classes/Network/PonyDebugger/FLEXNetworkObserver.m#L157
  'connectionDidFinishLoading:': {
    onEnter(args) {

    }
  },
  'connection:willSendRequest:redirectResponse:': {
    onEnter(args) {

    }
  },
  'connection:didReceiveResponse:': {
    onEnter(args) {

    }
  },
  'connection:didReceiveData:': {
    onEnter(args) {

    }
  },
  'connection:didFailWithError:': {
    onEnter(args) {

    }
  },
  'URLSession:task:willPerformHTTPRedirection:newRequest:completionHandler:': {
    onEnter(args) {

    }
  },
  'URLSession:dataTask:didReceiveData:': {
    onEnter(args) {

    }
  },
  'URLSession:dataTask:didReceiveResponse:completionHandler:': {
    onEnter(args) {
      console.log(reqid(args[3]))
      const response = new ObjC.Object(args[4])
      console.log('<', response.statusCode(), response.valueForHTTPHeaderField_('Content-Length'))
      console.log(headers(response.allHeaderFields()))
    }
  },
  'URLSession:task:didCompleteWithError:': {
    onEnter(args) {
      console.log(reqid(args[3]))
      const error = new ObjC.Object(args[4])
      console.log(error)
    }
  },
  'URLSession:dataTask:didBecomeDownloadTask:': {
    onEnter(args) {

    }
  },
  'URLSession:downloadTask:didWriteData:totalBytesWritten:totalBytesExpectedToWrite:': {
    onEnter(args) {

    }
  },
  'URLSession:downloadTask:didFinishDownloadingToURL:': {
    onEnter(args) {

    }
  },

  // https://github.com/Flipboard/FLEX/blob/b38cca06b/Classes/Network/PonyDebugger/FLEXNetworkObserver.m#L275
  'af_resume': { // AFNetworking
    onEnter(args) {

    }
  },

  // https://github.com/Flipboard/FLEX/blob/b38cca06b/Classes/Network/PonyDebugger/FLEXNetworkObserver.m#L500
  'dataTaskWithRequest:completionHandler:': dataTaskHookHandler,
  'dataTaskWithURL:completionHandler:': dataTaskHookHandler,
  'downloadTaskWithRequest:completionHandler:': dataTaskHookHandler,
  'downloadTaskWithResumeData:completionHandler:': dataTaskHookHandler,
  'downloadTaskWithURL:completionHandler:': dataTaskHookHandler,

  // https://github.com/Flipboard/FLEX/blob/b38cca06b/Classes/Network/PonyDebugger/FLEXNetworkObserver.m#L568
  'uploadTaskWithRequest:fromData:completionHandler:': uploadTaskHookHandler,
  'uploadTaskWithRequest:fromFile:completionHandler:': uploadTaskHookHandler
}

const mapping: { [key: string]: ObjC.Object } = {}

export function init() {
  const resolver = new ApiResolver('objc')
  for (const [sel, handler] of Object.entries(handlers)) {
    for (const match of resolver.enumerateMatches(`-[* ${sel}]`)) {
      // console.log(subject, match.name)
      // const clazz = match.name.substr(2, match.name.indexOf(' ') - 2)
      // for (const protocol of Object.keys(ObjC.classes[clazz].$protocols)) {
      //   protocols.add(protocol)
      // }
      Interceptor.attach(match.address, {
        onEnter(args: InvocationArguments) {
          this.method = match.name
          console.log(match.name)
          if (handler.onEnter) handler.onEnter.call(this, args)
        },
        onLeave(retval: InvocationReturnValue) {
          if (handler.onLeave) handler.onLeave?.call(this, retval)
        }
      })
    }
  }

  for (const clazz of ['__NSCFLocalSessionTask', 'NSURLSessionTask', '__NSCFURLSessionTask']) {
    const cls = ObjC.classes[clazz]
    if (!cls) continue
    const method = cls['- resume'] as ObjC.ObjectMethod
    if (!method) continue
    Interceptor.attach(method.implementation, {
      onEnter(args) {
        // todo:
      }
    })
  }

  Interceptor.attach(ObjC.classes.NSURLConnection['- cancel'].implementation, {
    onEnter(args) {

    }
  })
}

export function dispose() {

}
