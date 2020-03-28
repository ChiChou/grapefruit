// import { Session, Script } from 'frida'

// enum Status {
//   OK = 'ok',
//   FAIL = 'fail',
// }

// interface Result {
  
// }

// export default class Repl {
//   session: Session
//   scripts: Map<string, Script>

//   constructor(session) {
//     this.session = session
//     this.scripts = new Map()
//   }

//   /**
//    * execute user script
//    * @param {string} script 
//    */
//   async execute(source) {
//     const { socket, session } = this
//     const script = await session.createScript(`
//       rpc.exports.bootstrap = function(js) {
//         ['log', 'warn', 'error'].forEach(function(level) {
//           console[level] = function() {
//             send({
//               subject: 'console.message',
//               level: level,
//               args: [].slice.call(arguments)
//             });
//           };
//         });

//         try {
//           const result = (1, eval)(js);
//           if (result instanceof ArrayBuffer) {
//             return result;
//           } else {
//             var type = (result === null) ? 'null' : typeof result;
//             return [type, result];
//           }
//         } catch (e) {
//           return ['error', e instanceof Error ? {
//             name: e.name,
//             message: e.message,
//             stack: e.stack
//           } : e + ''];
//         }
//       }
//     `)

//     script.destroyed.connect(() => {
//       socket.emit('userScript', {
//         subject: 'destroyed',
//         uuid,
//       })
//     })

//     script.message.connect((message, data) => {
//       const { type, payload } = message
//       // forward to frontend
//       socket.emit('userScript', {
//         subject: 'message',
//         uuid,
//         type,
//         payload,
//         // binary data is not supported right now
//         hasData: data !== null,
//       })
//     })
    
//     let type, value
//     try {
//       await script.load()
//       type, value = await script.exports.bootstrap(source)
//     } catch (error) {
//       console.error('Uncaught user frida script', error.stack || error)
//       return {
//         status: 'failed',
//         error,
//       }
//     }

//     if (result instanceof Buffer) {
//       type = 'arraybuffer'
//       value = Buffer.from(result).toString('base64')
//     }

//     this.scripts.set(uuid, script)

//     if (type === 'error') {
//       console.error('Uncaught user frida script', value.stack || value)
//       return {
//         status: 'failed',
//         error: value,
//       }
//     }

//     return {
//       status: 'ok',
//       uuid,
//       type,
//       value,
//     }
//   }

//   async unload(uuid) {
//     if (!this.scripts.has(uuid))
//       throw new Error(`script not found: ${uuid}`)

//     const script = this.scripts.get(uuid)
//     this.scripts.delete(uuid)
//     return script.unload()
//   }
// }
