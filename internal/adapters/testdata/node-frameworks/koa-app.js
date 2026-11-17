// Koa with @koa/router. The router's methods read like Express's, which is why
// the generic extractor reaches them, and the mount prefix does not: a koa
// router carries its own prefix rather than taking one at use() time.
'use strict';

const Koa = require('koa');
const Router = require('@koa/router');

const app = new Koa();
const router = new Router({ prefix: '/koa' });

router.get('/tickets/:id', async (ctx) => {
  ctx.body = { id: ctx.params.id };
});

router.post('/tickets', async (ctx) => {
  ctx.body = { ok: true };
});

app.use(router.routes());

module.exports = app;
