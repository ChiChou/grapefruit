import Koa from 'koa'
import Router from 'koa-router'
import bodyParser from 'koa-bodyparser'
import logger from 'koa-logger'
import KoaJSON from 'koa-json'
import send from 'koa-send'

import * as path from 'path'
import * as frida from 'frida'

import * as serialize from './lib/serialize'
import { wrap } from './lib/device'
import { InvalidDeviceError, VersionMismatchError } from './lib/error'
import { Lockdown } from './lib/lockdown'
import { URL } from 'url'


// eslint-disable-next-line @typescript-eslint/explicit-function-return-type
Buffer.prototype.toJSON = function () {
  return this.toString('base64')
}

const app = new Koa()
const router = new Router({ prefix: '/api' })

const mgr = frida.getDeviceManager()

function tryGetDevice(id: string): Promise<frida.Device> {
  try {
    return id === 'usb' ? frida.getUsbDevice() : frida.getDevice(id)
  } catch (ex) {
    if (ex.message.startsWith('Unable to connect to remote frida-server'))
      throw new InvalidDeviceError(id)
    if (ex.message.startsWith('Unable to communicate with remote frida-server'))
      throw new VersionMismatchError(ex.message)
    else
      throw ex
  }
}

router
  .get('/devices', async (ctx) => {
    const devices = await mgr.enumerateDevices()
    ctx.body = {
      version: require('frida/package.json').version,
      list: devices.map(wrap).map(d => d.valueOf())
    }
  })
  .get('/device/:device/screen', async (ctx) => {
    const id = ctx.params.device
    const dev = await tryGetDevice(id)
    const shot = new Lockdown(dev, 'com.apple.mobile.screenshotr')
    await shot.connect()
    shot.send({ 'MessageType': 'ScreenShotRequest' })
    const response = await shot.recv()
    ctx.set('Content-Type', 'image/png')
    ctx.body = response.ScreenShotData
    shot.close()
  })
  .get('/device/:device/apps', async (ctx) => {
    const id = ctx.params.device
    const dev = await tryGetDevice(id)
    const apps = await dev.enumerateApplications()
    ctx.body = apps.map(serialize.app)
  })
  .get('/device/:device/info', async (ctx) => {
    const id = ctx.params.device
    const dev = await tryGetDevice(id)
    const client = new Lockdown(dev)
    await client.connect()
    client.send({
      'Request': 'GetValue'
    })
    const response = await client.recv()
    ctx.body = response.Value
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
    } catch(e) {
      ctx.status = 400
      ctx.body = { status: 'failed', error: e.message }
    }
  })
  .delete('/remote/:host', async (ctx) => {
    try {
      await mgr.removeRemoteDevice(ctx.params.host)
      ctx.body = { status: 'ok' }
    } catch(e) {
      ctx.status = 404
      ctx.body = { status: 'failed', error: e.message }
    }
  })

app
  .use(bodyParser())
  .use(async (ctx, next) => {
    try {
      await next()
    } catch(e) {
      if (process.env.NODE_ENV === 'development') {
        ctx.status = 500
        ctx.body = e.stack
      } else {
        ctx.throw(500, e)
      }
    }
  })
  .use(router.routes())
  .use(router.allowedMethods())

if (process.env.NODE_ENV === 'development') {
  app
    .use(KoaJSON({
      pretty: true
    }))
    .use(new Router().get('/', (ctx) => {
      const u = new URL(ctx.request.origin)
      u.port = '8080'
      ctx.redirect(u.toString())
      ctx.body = 'Passionfruit Development Server'
      ctx.status = 302
    }).routes())
} else {
  app.use(async (ctx, next) => {
    const opt = { root: path.join(__dirname, '..', 'gui', 'dist') }
    if (ctx.path.match(/^\/(css|fonts|js|img)\//))
      await send(ctx, ctx.path, opt)
    
    // else await send(ctx, '/index.html', opt)
    next()
  })
  app.use(logger())
}

app.listen(31337)