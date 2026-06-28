const path = require('node:path');
const fs = require('node:fs');
const esbuild = require('esbuild');

const profile = process.argv[2] || 'public';
const outfile = path.join(__dirname, 'dist', `${profile}.js`);

// Check private entries first, then public
let entry = path.join(__dirname, 'src', 'private', 'entries', `${profile}.js`);
if (!fs.existsSync(entry)) {
  entry = path.join(__dirname, 'src', 'entries', `${profile}.js`);
}

if (!fs.existsSync(entry)) {
  console.error(`❌ Entry file not found: ${entry}`);
  console.error(`   For the ${profile} profile, run from the project root with src/private/ installed.`);
  process.exit(1);
}

async function build() {
  const result = await esbuild.build({
    entryPoints: [entry],
    outfile,
    bundle: true,
    platform: 'node',
    target: 'node18',
    external: ['better-sqlite3', 'pg', 'bcrypt'],
    minify: true,
    sourcemap: true,
  });

  if (result.errors.length > 0) {
    console.error('Build failed:', result.errors);
    process.exit(1);
  }
  console.log(`✅ Built ${profile} profile → ${outfile}`);
}

build().catch(e => {
  console.error('Build failed:', e);
  process.exit(1);
});
