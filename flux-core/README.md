# flux-core

`flux-core` is a lightweight Go replacement for the original Java control service.

Goals:

- Keep the existing frontend API paths compatible where practical.
- Use SQLite directly and avoid a JVM runtime on low-memory machines.
- Keep public binary, database, and service names neutral.
- Add node expiration (`exp_time`) as a first-class central-control field.

Default environment:

| Variable | Default | Description |
| --- | --- | --- |
| `FLUX_CORE_ADDR` | `:6365` | HTTP listen address |
| `FLUX_DB_PATH` | `./data/panel.db` | SQLite database path |
| `JWT_SECRET` | `change-me` | JWT signing secret |
| `PUBLIC_ADDR` | empty | Public panel address used for node install commands |
| `AGENT_INSTALL_URL` | empty | Optional custom node install script URL |
| `AGENT_RELEASE_URL` | empty | Optional custom node binary release URL |
| `STATIC_DIR` | empty | Built frontend directory served by flux-core |

Run locally:

```bash
go run .
```

Build local binary:

```bash
go build -trimpath -ldflags="-s -w" -o flux-core.exe .
```

Native release package:

```bash
bash ../scripts/build_native_amd64.sh
```
