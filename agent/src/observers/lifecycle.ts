const name = `PassionfruitAppDelegate${Math.random().toString(36).slice(2)}`
const MyAppDelegate = ObjC.registerProtocol({
  name: name + 'Protocol',
  methods: {
    '- inactive': {
      retType: 'void',
      argTypes: [],
    },
    '- background': {
      retType: 'void',
      argTypes: [],
    }
  }
})

const center = ObjC.classes.NSNotificationCenter.defaultCenter()
const subject = 'lifecycle'
const Clazz = ObjC.registerClass({
  name,
  super: ObjC.classes.NSObject,
  protocols: [MyAppDelegate, ObjC.protocols.NSObject],
  methods: {
    '- inactive': () => {
      send({ subject, event: 'inactive' })
      console.warn('App will be inactive.')
    },
    '- background': () => {
      console.warn('App is is now on the background. Passionfruit will be inresponsible.')
      send({ subject, event: 'frozen' })
    },
    '- release': function() {
      // fix UAF
      dispose()
      this.super.release()
    }
  }
})

let signalHandler = Clazz.alloc().init()

export function init() {
  center.addObserver_selector_name_object_(
    signalHandler, ObjC.selector('inactive'), 'UIApplicationWillResignActiveNotification', NULL)
  center.addObserver_selector_name_object_(
    signalHandler, ObjC.selector('background'), 'UIApplicationDidEnterBackgroundNotification', NULL)
}

export function dispose() {
  if (!signalHandler) return
  center.removeObserver_name_object_(signalHandler, 'UIApplicationWillResignActiveNotification', NULL)
  center.removeObserver_name_object_(signalHandler, 'UIApplicationDidEnterBackgroundNotification', NULL)
  signalHandler = null
}
