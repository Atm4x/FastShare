const bcrypt = require('bcrypt');
const config = require('./config');

async function verifyPassword(inputPassword) {
  return await bcrypt.compare(inputPassword, config.PASSWORD_HASH);
}

module.exports = { verifyPassword };