const registry = [
  { name: 'status',     path: './status.route',     profiles: ['public', 'private'] },
  { name: 'session',    path: './session.route',     profiles: ['public', 'private'] },
  { name: 'leaderboard',path: './leaderboard.route', profiles: ['public', 'private'] },
  { name: 'pigeon',     path: './pigeon.route',      profiles: ['public', 'private'] },
  { name: 'abuse',      path: './abuse.route',       profiles: ['public', 'private'] },
  { name: 'auth',       path: './auth.route',        profiles: ['private'] },
  { name: 'launcher',   path: './launcher.route',    profiles: ['private'] },
];

function getRoutesForProfile(profile) {
  return registry.filter(r => r.profiles.includes(profile));
}

module.exports = { registry, getRoutesForProfile };
