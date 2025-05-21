import ObjC from 'frida-objc-bridge'

// const SEL selectors[] = {
//   @selector(connectionDidFinishLoading:),
//   @selector(connection:willSendRequest:redirectResponse:),
//   @selector(connection:didReceiveResponse:),
//   @selector(connection:didReceiveData:),
//   @selector(connection:didFailWithError:),
//   @selector(URLSession:task:willPerformHTTPRedirection:newRequest:completionHandler:),
//   @selector(URLSession:dataTask:didReceiveData:),
//   @selector(URLSession:dataTask:didReceiveResponse:completionHandler:),
//   @selector(URLSession:task:didCompleteWithError:),
//   @selector(URLSession:dataTask:didBecomeDownloadTask:),
//   @selector(URLSession:downloadTask:didWriteData:totalBytesWritten:totalBytesExpectedToWrite:),
//   @selector(URLSession:downloadTask:didFinishDownloadingToURL:)
// };

import { list } from '../modules/classdump.js'

const rawSelectors = `
@selector(connectionDidFinishLoading:),
@selector(connection:willSendRequest:redirectResponse:),
@selector(connection:didReceiveResponse:),
@selector(connection:didReceiveData:),
@selector(connection:didFailWithError:),
@selector(URLSession:task:willPerformHTTPRedirection:newRequest:completionHandler:),
@selector(URLSession:dataTask:didReceiveData:),
@selector(URLSession:dataTask:didReceiveResponse:completionHandler:),
@selector(URLSession:task:didCompleteWithError:),
@selector(URLSession:dataTask:didBecomeDownloadTask:),
@selector(URLSession:downloadTask:didWriteData:totalBytesWritten:totalBytesExpectedToWrite:),
@selector(URLSession:downloadTask:didFinishDownloadingToURL:)
`

const selectors = [...rawSelectors.matchAll(/@selector\(([\w:]+)\)/g)].map(m => m[1])
const context = {
  hooks: new Set<InvocationListener>()
}

// setup()

export function init() {
  const classes = list('__app__')
  for (const className of classes) {
    const clazz = ObjC.classes[className]
    if (!clazz) continue
    for (const sel of selectors) {
      if (typeof clazz[sel] === 'function') {
        console.log(className, sel)
      }      
    }
  }
}

export function dispose() {

}
