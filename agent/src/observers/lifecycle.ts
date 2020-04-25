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

const Clazz = ObjC.registerClass({
  name,
  super: ObjC.classes.NSObject,
  protocols: [MyAppDelegate],
  methods: {
    '- inactive': () => {
      console.warn('App will be inactive.')
    },
    '- background': () => {
      console.warn('App is is now on the background. Passionfruit will be inresponsible.')
    }
  }
})

const signalHandler = Clazz.alloc().init()
const center = ObjC.classes.NSNotificationCenter.defaultCenter()

export function init() {
  center.addObserver_selector_name_object_(
    signalHandler, ObjC.selector('inactive'), 'UIApplicationWillResignActiveNotification', NULL)
  center.addObserver_selector_name_object_(
    signalHandler, ObjC.selector('background'), 'UIApplicationDidEnterBackgroundNotification', NULL)
}

export function dispose() {
  const center = ObjC.classes.NSNotificationCenter.defaultCenter()
  center.removeObserver_name_object_(signalHandler, 'UIApplicationWillResignActiveNotification', NULL)
  center.removeObserver_name_object_(signalHandler, 'UIApplicationDidEnterBackgroundNotification', NULL)
}
