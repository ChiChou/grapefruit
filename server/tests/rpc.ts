import 'mocha'
import chaiAsPromised from 'chai-as-promised'
import * as frida from 'frida'
import { use, expect } from 'chai'

import { wrap, ExDevice } from '../lib/device'
import { proxy, connect, RPC } from "../lib/rpc"
import Repl from '../lib/repl'

use(chaiAsPromised)

describe('RPC', () => {
  let device: ExDevice, session: frida.Session, rpc: RPC, agent: frida.Script

  before(async () => {
    device = wrap(await frida.getUsbDevice())
    session = await device.start(process.env.APP || 'com.apple.mobilesafari')
    agent = await connect(session)

    await agent.load()

    // console.log(await __exports.interfaces())
    rpc = proxy(agent)
  })

  it('should execute user script', async () => {
    const repl = new Repl(session)
    repl.on('console', (uuid, level, args) => {
      console.log('[unittest] user script: ', uuid, level, ...args)
    })
    repl.on('scripterror', (err) => {
      console.log('[unittest] catched exception:', err)
    })

    await repl.eval('console.log(1)')
    const result = await repl.eval('Process.enumerateModules()[0].base.readByteArray(16)')
    expect(result.status).eq('ok')
    expect(result.value).instanceOf(ArrayBuffer)
    await repl.eval('console.log(2, Process.enumerateModules()[0].base.readByteArray(16))')
    await repl.eval('console.log(3, new Int8Array(10))')

    const err = await repl.eval('throw new Error("Runtime Error")')
    expect(err.error).is.not.null
    expect(err.status).eq('failed')

    await repl.eval('setTimeout(function() { throw new Error("should throw") }, 0)')
    await new Promise(resolve => setTimeout(resolve, 100))
    repl.destroy()
  })

  it('should handle basic RPC usage', async () => {
    expect(await rpc('cookies/list')).to.be.an('array')

    expect(await rpc.cookies.list()).to.be.an('array')
    expect(await rpc.checksec()).to.be.an('object')
      .and.to.has.keys(['entitlements', 'encrypted', 'arc', 'canary', 'pie'])
  })

  it('should support common modules', async () => {
    await rpc.syslog.start()

    expect(await rpc.device.info()).to.be.an('object')

    expect(await rpc.info.info()).to.be.an('object')
      .and.to.has.keys(['tmp', 'home', 'json', 'id', 'bundle', 'binary', 'urls', 'minOS', 'name', 'semVer', 'version'])
    expect(await rpc.info.userDefaults()).to.be.an('object')
    expect(await rpc.symbol.modules()).to.be.an('array')
    expect(await rpc.symbol.imps('MobileSafari')).to.be.an('array')
    expect(await rpc.symbol.exps('WebKit')).to.be.an('array')

    const BOOKMARKS = '/var/mobile/Library/Safari/Bookmarks.db'
    expect(await rpc.sqlite.tables(BOOKMARKS)).to.be.an('array')
    expect(await rpc.sqlite.query(BOOKMARKS, 'select count(*) from bookmarks')).to.be.an('array').and.have.lengthOf(1)
    expect(await rpc.sqlite.data(BOOKMARKS, 'bookmarks')).to.be.an('object').and.have.keys(['header', 'data'])

    expect(await rpc.keychain.list()).to.be.an('array')

    await rpc.syslog.stop()
  })

  it('should support filesystem api', async () => {
    const SAFARI_PREF = await rpc.fs.resolve('home', 'Library/Preferences/com.apple.mobilesafari.plist')

    expect(await rpc.fs.plist(SAFARI_PREF)).to.be.an('object')
    
    const library = await rpc.fs.ls('home', 'Library')
    expect(library.items).to.be.an('array')

    const bundle = await rpc.fs.ls('bundle')
    expect(bundle.items).to.be.an('array')
    // expect(rpc.fs.ls('bundle', 'nonexist-path')).to.be.rejected

    const WRITE_TARGET = await rpc.fs.resolve('home', 'tmp/hello' + Math.random())
    const WRITE_CONTENT = 'hello world' + Math.random().toString(16)
    const f1 = `${WRITE_TARGET}.bak`
    const f2 = `${WRITE_TARGET}.new`
    expect(await rpc.fs.write(WRITE_TARGET, WRITE_CONTENT)).to.be.true
    expect((await rpc.fs.text(WRITE_TARGET)).toString()).equals(WRITE_CONTENT)
    expect(await rpc.fs.copy(WRITE_TARGET, f1)).to.be.true
    expect(await rpc.fs.move(WRITE_TARGET, f2)).to.be.true
    expect((await rpc.fs.text(f2)).toString()).equals(WRITE_CONTENT) 
    expect(await rpc.fs.remove(f1)).to.be.true
    expect(await rpc.fs.remove(f2)).to.be.true

    agent.message.connect((message, data) => {
      const { payload } = message as unknown as { payload: { subject: string } }
      // expect(payload).to.include.key('subject')
      if (payload.subject === 'data')
        expect(data).to.be.instanceOf(Buffer)
    })

    await rpc.fs.download('/etc/hosts')
  })

  it('should dump classes', async () => {
    const main = await rpc.classdump.dump()
    const withFrameworks = await rpc.classdump.ownClasses()

    expect(main).to.be.an('array')
    expect(withFrameworks).to.be.an('array')
    expect(main.length).to.lte(withFrameworks.length)

    // eslint-disable-next-line @typescript-eslint/explicit-function-return-type
    const isTree = (node: object) => expect(node).to.be.an('object')

    // app scope
    isTree(await rpc.classdump.hierarchy('__app__'))
    // main module
    isTree(await rpc.classdump.hierarchy('__main__'))
    // // all classes (pretty slow)
    // isTree(await rpc.classdump.hierarchy('__global__'))
    // single module
    isTree(await rpc.classdump.hierarchy('/System/Library/Frameworks/UIKit.framework/UIKit'))
    // selected modules
    isTree(await rpc.classdump.hierarchy([
      '/System/Library/Frameworks/UIKit.framework/UIKit',
      '/System/Library/Frameworks/CFNetwork.framework/CFNetwork'
    ]))
  })

  after(async () => {
    if (session)
      await session.detach()
  })
})