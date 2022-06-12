import 'reflect-metadata'

import Koa from 'koa'
import Router from 'koa-router'
import bodyParser from 'koa-bodyparser'
import logger from 'koa-logger'
import KoaJSON from 'koa-json'
import send from 'koa-send'

import * as fs from 'fs'
import * as path from 'path'
import * as frida from 'frida'

import * as serialize from './lib/serialize'
import * as transfer from './lib/transfer'
import Channels from './lib/channels'

import { wrap, tryGetDevice } from './lib/device'

import { URL } from 'url'
import { exec } from 'child_process'
import { createServer } from 'http'
import { program } from 'commander'
import { AddressInfo } from 'net'
import { concat } from './lib/workspace'
import { Scope } from 'frida/dist/device'

const ISDEBUG = process.env.NODE_ENV === 'development'

// eslint-disable-next-line @typescript-eslint/explicit-function-return-type
Buffer.prototype.toJSON = function () {
  return this.toString('base64')
}

const app = new Koa()
const router = new Router({ prefix: '/api' })

const mgr = frida.getDeviceManager()

if (ISDEBUG) {
  router
    .get('/device/mock/apps', (ctx) => {
      ctx.body = new Array(5).fill({
        name: "Example",
        pid: 0,
        identifier: "com.example.mock"
      })
    })
    .get('/device/mock/icon/com.example.mock', (ctx) => {
      const folder = ISDEBUG ? '.' : '..'
      ctx.body = fs.createReadStream(path.join(__dirname, folder, 'templates', `mockicon.png`))
    })
}

router
  .get('/devices', async (ctx) => {
    const unique = new Set()
    const devices = await mgr.enumerateDevices()

    const list = devices.filter(dev => {
      if (dev.id === 'local' || dev.id === 'socket')
        return false

      if (unique.has(dev.id))
        return false

      unique.add(dev.id)
      return true
    }).map(wrap).map(d => d.valueOf())

    if (ISDEBUG) {
      list.push({
        name: 'Mock Device',
        id: 'mock',
        type: 'remote',
        removable: false
      })
    }

    ctx.body = {
      version: require('frida/package.json').version,
      node: process.version,
      list
    }
  })
  .get('/device/:device/apps', async (ctx) => {
    const id = ctx.params.device
    const dev = await tryGetDevice(id)
    const apps = await dev.enumerateApplications()
    ctx.body = apps.map(serialize.app)
  })
  .get('/device/:device/icon/:bundle', async (ctx) => {
    const id = ctx.params.device
    const dev = await tryGetDevice(id)
    const bundle = ctx.params.bundle
    const apps = await dev.enumerateApplications({
      identifiers: [bundle],
      scope: Scope.Full
    })
    if (!apps.length) ctx.throw(404, `app "${bundle}" not found`)
    const app = apps[0]
    const { icons } = app.parameters
    if (!icons || !icons.length) ctx.throw(404, 'icons unavaliable')
    const icon = icons.find(i => i.format === 'png')
    if (!icon || !icon.image) ctx.throw(404, 'Invalid icon format. Consider upgrading your frida on device')
    ctx.body = icon.image
  })
  .get('/device/:device/info', async (ctx) => {
    const id = ctx.params.device
    const dev = await tryGetDevice(id)
    ctx.body = await dev.querySystemParameters()
  })
  .get('/download/:uuid', async (ctx) => {
    const { uuid } = ctx.params
    try {
      const task = transfer.request(uuid)
      ctx.attachment(task.name)
      ctx.set('Cache-Control', 'max-age=7200')
      // https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Expose-Headers
      ctx.set('Access-Control-Expose-Headers', 'Content-Length')
      ctx.response.length = task.size
      ctx.body = task.stream
    } catch (e) {
      console.error('error', e)
      ctx.throw(404)
    }
  })
  .post('/url/start', async (ctx) => {
    const { device, bundle, url } = ctx.request.body
    const dev = await frida.getDevice(device)
    const pid = await dev.spawn([bundle], { url })
    await dev.resume(pid)
    ctx.body = { status: 'ok', pid }
  })
  .put('/remote/add', async (ctx) => {
    const { host } = ctx.request.body
    try {
      const dev = await mgr.addRemoteDevice(host)
      ctx.body = { status: 'ok', id: dev.id }
    } catch (e) {
      ctx.status = 400
      ctx.body = { status: 'failed', error: e.message }
    }
  })
  .delete('/remote/:host', async (ctx) => {
    try {
      await mgr.removeRemoteDevice(ctx.params.host)
      ctx.body = { status: 'ok' }
    } catch (e) {
      ctx.status = 404
      ctx.body = { status: 'failed', error: e.message }
    }
  })
  .get('/update', async (ctx) => {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const task = new Promise((resolve, reject) =>
      exec('npm view passionfruit version', (err, stdout) =>
        err ? reject(err) : resolve(stdout.trimRight())
      )
    )

    const current = require('../package.json').version
    try {
      const latest = await task
      ctx.body = {
        current,
        latest
      }
    } catch (err) {
      ctx.throw(500, `failed to check update\n${err}`)
    }
  })
  .get('/types', async (ctx) => {
    const base = require.resolve('frida/package.json')
    ctx.body = fs.createReadStream(path.join(base, '..', '..', '@types', 'frida-gum', 'index.d.ts'))
  })
  .get('/template/:name', async (ctx) => {
    const name = `${ctx.params.name}`.toLowerCase()
    const valid = /^(intercept|pointer|swizzling)$/
    if (!name.match(valid)) {
      ctx.body = 'invalid name'
      ctx.status = 400
      return
    }
    const folder = ISDEBUG ? '.' : '..'
    ctx.body = fs.createReadStream(path.join(__dirname, folder, 'templates', `${name}.js`))
  })

app
  .use(bodyParser())
  .use(async (ctx, next) => {
    try {
      await next()
    } catch (e) {
      if (ISDEBUG) {
        ctx.status = 500
        ctx.body = e.stack
      } else {
        ctx.throw(500, e)
      }
    }
  })

if (ISDEBUG) {
  app
    .use(KoaJSON({
      pretty: true
    }))
    .use(new Router().get('/', (ctx) => {
      const u = new URL(ctx.request.origin)
      u.port = '8080'
      ctx.redirect(u.toString())
      ctx.body = 'Grapefruit Development Server'
      ctx.status = 302
    }).routes())
} else {
  app.use(async (ctx, next) => {
    const root = path.join(__dirname, '..', '..', 'gui', 'dist')
    const opt = { root }
    if (ctx.path.startsWith('/api')) {
      await next()
    } else if (ctx.path.match(/(^\/(css|fonts|js|img)\/|\.js(.map)?$)/)) {
      await send(ctx, ctx.path, opt)
    } else if (ctx.path === '/picker.html') {
      await send(ctx, '/picker.html', opt)
    } else {
      await send(ctx, '/index.html', opt)
    }
  })
  app.use(logger())
}

async function main(): Promise<void> {
  const base = concat('scripts')
  router
    .param('script', (script, ctx, next) => {
      if (!script.match(/^[\w-_\.]+\.[jt]s$/)) {
        ctx.status = 404
        return
      }
      return next()
    })
    .get('/snippets', async (ctx) => {
      try {
        ctx.body = await fs.promises.readdir(base)
      } catch (e) {
        ctx.status = 404
        ctx.body = 'user scripts not found'
      }
    })
    .delete('/snippet/:script', async (ctx) => {
      const abs = path.join(base, ctx.params.script)
      try {
        await fs.promises.access(abs, fs.constants.F_OK)
        await fs.promises.unlink(abs)
      } catch(e) {
        ctx.status = 404
        return
      }
      ctx.body = 'ok'
    })
    .put('/snippet/:script', async (ctx) => {
      const abs = path.join(base, ctx.params.script)
      ctx.req.pipe(fs.createWriteStream(abs))
      ctx.body = 'ok'
    })
    .get('/snippet/:script', async (ctx) => {
      const abs = path.join(base, ctx.params.script)
      const mapping = {
        ts: 'type',
        js: 'java'
      }
      const lang = mapping[path.extname(ctx.params.script)]
      ctx.set('Content-Type', `text/${lang}script`)
      ctx.body = fs.createReadStream(abs)
    })

  app.use(router.routes())
    .use(router.allowedMethods())

  program
    .name('igf')
    .option('-h, --host <string>', 'hostname', '127.0.0.1')
    .option('-p, --port <number>', 'port of the server side', (val) => parseInt(val, 10), 31337)

  program.parse(process.argv)

  const server = createServer(app.callback())
  const channels = new Channels(server)
  channels.connect()
  server.listen(program.port, program.host)
  server.on('listening', () => {
    const addr = server.address() as AddressInfo
    console.log(`Grapefruit running on http://${addr.address}:${addr.port}`)
  })
  process.on('exit', () => channels.disconnect())
}

main()
