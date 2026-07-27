/* Run with: npm run seed
 * Creates (or resets) the default admin account.
 * Override credentials with SEED_ADMIN_EMAIL / SEED_ADMIN_PASSWORD env vars.
 */
require('dotenv').config();
const { v4: uuid } = require('uuid');
const { writeCollection } = require('../src/utils/jsonStore');
const { hashPassword } = require('../src/utils/passwords');

async function main() {
  const email = process.env.SEED_ADMIN_EMAIL || 'admin@cimi.gov.in';
  const password = process.env.SEED_ADMIN_PASSWORD || 'ChangeMe!123';

  const passwordHash = await hashPassword(password);

  const users = [
    {
      id: uuid(),
      name: 'Security Analyst',
      email,
      role: 'admin',
      passwordHash,
      createdAt: new Date().toISOString(),
    },
  ];

  writeCollection('users', users);

  console.log('Seeded 1 user:');
  console.log(`  email:    ${email}`);
  console.log(`  password: ${password}`);
  console.log('Change this password after first login.');
}

main().catch((err) => {
  console.error('Seed failed:', err);
  process.exit(1);
});
