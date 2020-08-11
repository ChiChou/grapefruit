import 'reflect-metadata'

import Koa from 'koa'
import Router from 'koa-router'
import bodyParser from 'koa-bodyparser'
import logger from 'koa-logger'
import KoaJSON from 'koa-json'
import send from 'koa-send'

import * as path from 'path'
import * as frida from 'frida'

import * as serialize from './lib/serialize'
import * as transfer from './lib/transfer'
import Channels from './lib/channels'

import { Event } from './models/Event'
import { Tag } from './models/Tag'
import { Snippet } from './models/Snippet'

import * as pkg from './package.json'

import { wrap, tryGetDevice } from './lib/device'
import { Lockdown } from './lib/lockdown'

import { URL } from 'url'
import { exec } from 'child_process'
import { createServer } from 'http'
import { program } from 'commander'
import { AddressInfo } from 'net'
import { connect } from './lib/db'


// eslint-disable-next-line @typescript-eslint/explicit-function-return-type
Buffer.prototype.toJSON = function () {
  return this.toString('base64')
}

const app = new Koa()
const router = new Router({ prefix: '/api' })

const mgr = frida.getDeviceManager()


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
    ctx.set('Cache-Control', 'max-age=60')
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

app
  .use(bodyParser())
  .use(async (ctx, next) => {
    try {
      await next()
    } catch (e) {
      if (process.env.NODE_ENV === 'development') {
        ctx.status = 500
        ctx.body = e.stack
      } else {
        ctx.throw(500, e)
      }
    }
  })

if (process.env.NODE_ENV === 'development') {
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
    const opt = { root: path.join(__dirname, '..', 'gui', 'dist') }
    if (ctx.path.match(/^\/(css|fonts|js|img)\//))
      await send(ctx, ctx.path, opt)

    // else await send(ctx, '/index.html', opt)
    next()
  })
  app.use(logger())
}

interface AddSnippetSchema {
  name: string;
  tags: string[];
  source: string;
}

async function main(): Promise<void> {
  const conn = await connect()

  router
    .get('/snippets', async (ctx) => {
      const page = ctx.params.p
      const repo = conn.getRepository(Snippet);
      const [all, count] = await repo.findAndCount({
        take: 100,
        skip: page ? parseInt(page) * 100 : null
      })

      ctx.body = {
        all,
        count
      }
    })
    .put('/snippets', async (ctx) => {
      const { name, tags, source } = ctx.request.body as AddSnippetSchema
      const snippet = new Snippet()
      snippet.name = name
      snippet.tags = tags.map(tag => {
        const t = new Tag()
        t.name = tag
        return t
      })
      snippet.source = source
      const repo = conn.getRepository(Snippet)
      const saved = await repo.save(snippet)

      ctx.body = { status: 'ok', id: saved.id }
    })

  app.use(router.routes())
    .use(router.allowedMethods())

  program
    .version(pkg.version)
    .option('-p, --port <number>', 'port of the server side', (val) => parseInt(val, 10), 31337)

  program.parse(process.argv)

  const server = createServer(app.callback())
  const channels = new Channels(server)
  channels.connect()
  server.listen(program.port)
  server.on('listening', () => {
    const addr = server.address() as AddressInfo
    console.log(`Grapefruit running on http://${addr.address}:${addr.port}`)
  })
  process.on('exit', () => channels.disconnect())
}

main()
