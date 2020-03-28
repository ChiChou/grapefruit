import "mocha"
import chaiAsPromised from 'chai-as-promised'
import * as frida from 'frida'
import { use, expect } from 'chai'

import { wrap, ExDevice } from '../lib/device'
import { proxy, connect, RPC } from "../lib/rpc"

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

  it('should handle basic RPC usage', async () => {
    expect(await (rpc as Function)('cookies/list')).to.be.an('array')

    expect(await rpc.cookies.list()).to.be.an('array')
    expect(await rpc.checksec()).to.be.an('object')
      .and.to.has.keys(['entitlements', 'encrypted', 'arc', 'canary', 'pie'])

    // expect(rpc.non.exist()).to.be.rejected
    expect(() => delete rpc.symbol).to.be.throw
    expect(() => rpc.foo = 'bar').to.be.throw
  })

  it('should support common modules', async () => {
    await rpc.syslog.start()

    expect(await rpc.device.info()).to.be.an('object')

    expect(await rpc.info.info()).to.be.an('object')
      .and.to.has.keys(['tmp', 'home', 'json', 'id', 'bundle', 'binary', 'urls', 'minOS', 'name', 'semVer', 'version'])
    expect(await rpc.info.userDefaults()).to.be.an('object')
    expect(await rpc.symbol.modules()).to.be.an('array')
    expect(await rpc.symbol.imports('MobileSafari')).to.be.an('array')
    expect(await rpc.symbol.exports('WebKit')).to.be.an('array')

    const BOOKMARKS = '/var/mobile/Library/Safari/Bookmarks.db'
    expect(await rpc.sqlite.tables(BOOKMARKS)).to.be.an('array')
    expect(await rpc.sqlite.query(BOOKMARKS, 'select count(*) from bookmarks')).to.be.an('array').and.have.lengthOf(1)
    expect(await rpc.sqlite.data(BOOKMARKS, 'bookmarks')).to.be.an('object').and.have.keys(['header', 'data'])

    expect(await rpc.keychain.list()).to.be.an('array')

    await rpc.syslog.stop()
  })

  it('should support filesystem api', async() => {
    const SAFARI_PREF = await rpc.fs.resolve('home', 'Library/Preferences/com.apple.mobilesafari.plist')

    expect(await rpc.fs.plist(SAFARI_PREF)).to.be.an('object')
    expect(await rpc.fs.ls('home', 'Library')).to.be.an('array')
    expect(await rpc.fs.ls('bundle')).to.be.an('array')
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
      const { payload } = message as any
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

    const isTree = node => expect(node).to.be.an('object')

    // app scope
    isTree(await rpc.classdump.hierarchy('__app__'))
    // main module
    isTree(await rpc.classdump.hierarchy('__main__'))
    // all classes (pretty slow)
    isTree(await rpc.classdump.hierarchy('__global__'))
    // single module
    isTree(await rpc.classdump.hierarchy('/System/Library/Frameworks/UIKit.framework/UIKit'))
    // selected modules
    isTree(await rpc.classdump.hierarchy([
      '/System/Library/Frameworks/UIKit.framework/UIKit',
      '/System/Library/Frameworks/CFNetwork.framework/CFNetwork'
    ]))
  })

  it('should capture a screenshot', async () => {
    const { writeFile } = require('fs')
    const { tmpdir } = require('os')
    const { join } = require('path')
    const { promisify } = require('util')

    const write = promisify(writeFile)
    const filename = join(tmpdir(), `${Math.random().toString(36)}.png`)
    const buf = await rpc.screenshot()

    expect(buf).to.be.an.instanceOf(Buffer)
    if (process.env.DEBUG_SAVE_SCREENSHOT) {
      await write(filename, buf)
      console.info(`\t[INFO] open ${filename} to see the picture`)
    }
  })

  after(async () => {
    if (session)
      await session.detach()
  })
})