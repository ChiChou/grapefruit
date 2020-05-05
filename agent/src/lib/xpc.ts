import { dl } from './native'

const getsectiondata = new NativeFunction(
  dl('libmacho.dylib').sym('getsectiondata')!,
  'pointer',
  ['pointer', 'pointer', 'pointer', 'pointer']
)

const libxpc = dl('libxpc.dylib')

// https://opensource.apple.com/source/xnu/xnu-792/osfmk/mach/port.h
//
// #define MACH_PORT_NULL		0  /* intentional loose typing */
// #define MACH_PORT_DEAD		((mach_port_name_t) ~0)
// #define MACH_PORT_VALID(name)				\
// 		(((name) != MACH_PORT_NULL) && 		\
// 		 ((name) != MACH_PORT_DEAD))

const MACH_PORT_NULL = 0
const MACH_PORT_DEAD = 0xffffffff
const bootstrap_look_up = new NativeFunction(libxpc.sym('bootstrap_look_up'), 'pointer', ['pointer', 'pointer', 'pointer'])
const bootstrap_port = libxpc.sym('bootstrap_port')
const mach_task_self_ = libxpc.sym('mach_task_self_')
const mach_port_deallocate = new NativeFunction(libxpc.sym('mach_port_deallocate'), 'void', ['pointer', 'uint32'])

const NSPropertyListImmutable = 0
const { NSData, NSPropertyListSerialization } = ObjC.classes

interface Service {
  name: string;
  path: string;
  access: boolean;
}

export function * services(): IterableIterator<Service> {
  const cache = '/System/Library/Caches/com.apple.xpcd/xpcd_cache.dylib'

  const pSize = Memory.alloc(Process.pointerSize)
  const address = getsectiondata(
    Module.load(cache).base,
    Memory.allocUtf8String('__TEXT'),
    Memory.allocUtf8String('__xpcd_cache'),
    pSize) as NativePointer  

  if (address.isNull()) return

  const size = pSize.readUInt()
  const format = Memory.alloc(Process.pointerSize)
  const err = Memory.alloc(Process.pointerSize).writePointer(NULL)
  const data = NSData.dataWithBytesNoCopy_length_freeWhenDone_(address, size, 0)
  const dict = NSPropertyListSerialization.propertyListFromData_mutabilityOption_format_errorDescription_(
    data,
    NSPropertyListImmutable,
    format,
    err,
  )

  const desc = err.readPointer()
  if (!desc.isNull())
    throw new Error(new ObjC.Object(desc).toString())
  
  const daemons = dict.objectForKey_('LaunchDaemons')
  const keys = daemons.allKeys()
  const count = keys.count()
  const pPort = Memory.alloc(Process.pointerSize)

  for (let i = 0; i < count; i++) {
    const key = keys.objectAtIndex_(i).toString()
    const obj = daemons.objectForKey_(key)
    const prog = obj.objectForKey_('Program')
    const args = obj.objectForKey_('ProgramArguments')

    let path = prog
    if (!path && args) {
      path = args.objectAtIndex_(0)
    } else {
      path = 'N/A'
    }

    const services = obj.objectForKey_('MachServices')
    if (!services) continue

    const servicesNames = services.allKeys()
    const servicesCount = servicesNames.count()

    for (let j = 0; j < servicesCount; j++) {
      const name = servicesNames.objectAtIndex_(j)
      if ((bootstrap_look_up(bootstrap_port, Memory.allocUtf8String(name.toString()), pPort) as NativePointer).isNull()) {
        const port = pPort.readU32()
        let access = false
        if (port !== MACH_PORT_NULL && port !== MACH_PORT_DEAD) {
          access = true
          mach_port_deallocate(mach_task_self_, port)
        }

        yield {
          access,
          name,
          path
        }
      }  
    }
  }
}

// [...services()]
