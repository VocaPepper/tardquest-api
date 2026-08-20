# TardQuest API

Node.js/Express API server for the TardQuest dungeon-crawler. It is a rewrite of the original Python/Flask server and provides the public gameplay API.

## Quick start

```bash
npm install
npm run build:public
npm run start:public
```

The public server listens on `http://0.0.0.0:9601` by default. Configuration defaults are in `server.config.js`; environment overrides are loaded from `.env`.

## Development

```bash
npm test
npm run build:public
```

Use `npm run dev:public` for Node's watch mode.

## Documentation

See [docs/public/README.md](docs/public/README.md) for the public API, configuration, database schema, and security behavior.

## License

This project is released under the [MIT License](LICENSE). You may use, modify, and redistribute it under those terms.
