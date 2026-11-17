# SCIM Server

Minimal SCIM 2.0 `/Users` server (in-memory storage, bearer-token auth).

- `GET/POST /scim/v2/Users`, `GET/PUT/PATCH/DELETE /scim/v2/Users/:id`
- `GET /scim/v2/ServiceProviderConfig`, `GET /health`
- Filter support: `?filter=userName eq "bob"`

Run: `SCIM_TOKEN=secret npm start`

Deploy: connect the repo in Render (Blueprint uses `render.yaml`); `SCIM_TOKEN` is auto-generated.
Note: data is lost on restart.
# scim-sample
