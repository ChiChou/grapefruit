import Koa from 'koa'
import Router from 'koa-router'

const app = new Koa()
const router = new Router({ prefix: '/api' })

router.get('/', async (ctx) => {
  ctx.body = 'hello'
})

app
  .use(router.routes())
  .use(router.allowedMethods())
  .listen(31337)
