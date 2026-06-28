# TardQuest API

Game API server for TardQuest, a JavaScript dungeon-crawler web game. Node.js/Express rewrite of the original Python/Flask server.

## Quick start

```bash
npm install
npm run build
node dist/public.js
```

No configuration required — all defaults in `server.config.js`.

## Tests

```bash
npm test
```

## Project layout

```
server.config.js         # All default settings
src/
├── entries/             # Entry points
├── routes/              # Route handlers
├── middleware/          # Express middleware
├── services/            # Business logic
├── db/                  # SQLite
├── config.js            # Config loader (merges config + .env)
└── utils/               # Logging, validation
tests/
├── unit/
└── integration/
docs/public/             # Public documentation
```

## Documentation

See [`docs/public/README.md`](./docs/public/README.md) for the full public API reference, configuration options, database schema, and security overview.
