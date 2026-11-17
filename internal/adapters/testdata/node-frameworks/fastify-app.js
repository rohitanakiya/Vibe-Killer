// Fastify, in both of its route-declaring styles.
//
// The shorthand is the same shape as Express's, so the generic extractor
// reaches it. The object form is the one that needs its own handling, and it
// does not promise a key order: method-then-url and url-then-method are both
// ordinary fastify.
'use strict';

const fastify = require('fastify')({ logger: false });

fastify.get('/fastify/orders/:id', async (request) => {
  return { id: request.params.id };
});

fastify.post('/fastify/orders', async () => {
  return { ok: true };
});

fastify.route({
  method: 'GET',
  url: '/fastify/reports/:year',
  handler: async (request) => ({ year: request.params.year }),
});

fastify.route({
  url: '/fastify/exports',
  method: 'DELETE',
  handler: async () => ({ ok: true }),
});

module.exports = fastify;
