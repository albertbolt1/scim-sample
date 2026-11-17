const http = require('http');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const TOKEN = process.env.SCIM_TOKEN || 'secret-token';
const USER_SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:User';
const LIST_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:ListResponse';
const ERR_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:Error';

const users = new Map();

function send(res, status, body) {
  res.writeHead(status, { 'Content-Type': 'application/scim+json' });
  res.end(body === undefined ? '' : JSON.stringify(body));
}

function error(res, status, detail) {
  send(res, status, { schemas: [ERR_SCHEMA], status: String(status), detail });
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (c) => (data += c));
    req.on('end', () => {
      try { resolve(data ? JSON.parse(data) : {}); } catch (e) { reject(e); }
    });
  });
}

function withMeta(user, base) {
  return { ...user, meta: { ...user.meta, location: `${base}/scim/v2/Users/${user.id}` } };
}

// Supports: attr eq "value" (e.g. userName eq "bob")
function matchFilter(user, filter) {
  if (!filter) return true;
  const m = filter.match(/^(\w+(?:\.\w+)*)\s+eq\s+"(.*)"$/i);
  if (!m) return true;
  const val = m[1].split('.').reduce((o, k) => (o ? o[k] : undefined), user);
  return String(val).toLowerCase() === m[2].toLowerCase();
}

// Minimal PATCH: add/replace/remove on top-level or dotted paths
function applyPatch(user, ops) {
  for (const op of ops) {
    const verb = (op.op || '').toLowerCase();
    if (!op.path) {
      if (verb !== 'remove') Object.assign(user, op.value);
      continue;
    }
    const keys = op.path.split('.');
    const last = keys.pop();
    let target = user;
    for (const k of keys) target = target[k] = target[k] || {};
    if (verb === 'remove') delete target[last];
    else target[last] = op.value;
  }
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const base = `${req.headers['x-forwarded-proto'] || 'http'}://${req.headers.host}`;

  if (url.pathname === '/health') return send(res, 200, { status: 'ok' });

  if (req.headers.authorization !== `Bearer ${TOKEN}`) {
    return error(res, 401, 'Unauthorized');
  }

  if (url.pathname === '/scim/v2/ServiceProviderConfig') {
    return send(res, 200, {
      schemas: ['urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig'],
      patch: { supported: true },
      bulk: { supported: false },
      filter: { supported: true, maxResults: 100 },
      changePassword: { supported: false },
      sort: { supported: false },
      etag: { supported: false },
      authenticationSchemes: [{ type: 'oauthbearertoken', name: 'Bearer Token', description: 'Bearer token auth' }],
    });
  }

  const m = url.pathname.match(/^\/scim\/v2\/Users(?:\/([^/]+))?$/);
  if (!m) return error(res, 404, 'Not found');
  const id = m[1];

  try {
    if (!id && req.method === 'GET') {
      const all = [...users.values()].filter((u) => matchFilter(u, url.searchParams.get('filter')));
      const start = Math.max(parseInt(url.searchParams.get('startIndex') || '1', 10), 1);
      const count = Math.min(parseInt(url.searchParams.get('count') || '100', 10), 100);
      const page = all.slice(start - 1, start - 1 + count).map((u) => withMeta(u, base));
      return send(res, 200, { schemas: [LIST_SCHEMA], totalResults: all.length, startIndex: start, itemsPerPage: page.length, Resources: page });
    }

    if (!id && req.method === 'POST') {
      const body = await readBody(req);
      if (!body.userName) return error(res, 400, 'userName is required');
      if ([...users.values()].some((u) => u.userName.toLowerCase() === body.userName.toLowerCase())) {
        return error(res, 409, 'userName already exists');
      }
      const now = new Date().toISOString();
      const user = { ...body, schemas: [USER_SCHEMA], id: crypto.randomUUID(), active: body.active !== false,
        meta: { resourceType: 'User', created: now, lastModified: now } };
      users.set(user.id, user);
      return send(res, 201, withMeta(user, base));
    }

    if (id) {
      const user = users.get(id);
      if (!user) return error(res, 404, 'User not found');

      if (req.method === 'GET') return send(res, 200, withMeta(user, base));

      if (req.method === 'PUT') {
        const body = await readBody(req);
        const updated = { ...body, schemas: [USER_SCHEMA], id, meta: { ...user.meta, lastModified: new Date().toISOString() } };
        users.set(id, updated);
        return send(res, 200, withMeta(updated, base));
      }

      if (req.method === 'PATCH') {
        const body = await readBody(req);
        applyPatch(user, body.Operations || []);
        user.meta.lastModified = new Date().toISOString();
        return send(res, 200, withMeta(user, base));
      }

      if (req.method === 'DELETE') {
        users.delete(id);
        return send(res, 204);
      }
    }
    return error(res, 405, 'Method not allowed');
  } catch (e) {
    return error(res, 400, 'Invalid JSON body');
  }
});

server.listen(PORT, () => console.log(`SCIM server listening on :${PORT}`));
