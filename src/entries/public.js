const { buildApp } = require('../buildApp');
const { listen } = require('../server');

const publicRoutes = [
  require('../routes/status.route'),
  require('../routes/session.route'),
  require('../routes/leaderboard.route'),
  require('../routes/pigeon.route'),
  require('../routes/abuse.route'),
];

const app = buildApp(publicRoutes);
listen(app).catch(e => {
  console.error('Fatal startup error:', e);
  process.exit(1);
});
