import Koa from 'koa'
import Router from 'koa-router'

const app = new Koa()
const router = new Router({ prefix: '/api' })

router
  .get('/', async (ctx) => {
    ctx.body = 'hello'
  })
  .get('/devices', async (ctx) => {
    ctx.body = {
      version: require('frida/package.json').version
    }
  })

app
  .use(router.routes())
  .use(router.allowedMethods())
  .listen(31337)
