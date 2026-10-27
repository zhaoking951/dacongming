const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const sub = require('../src/utils/vless');
const node = { name: 'test', host: 'example.invalid', port: 443,
  uuid: '00000000-0000-4000-8000-000000000001',
  reality_public_key: 'fixture-key', reality_short_id: '0123456789abcdef' };

test('single and mixed Clash REALITY subscriptions enable X25519MLKEM768', () => {
  for (const output of [sub.generateClashSubForUser([node]), sub.generateClashAllSub([node], [])]) {
    assert.match(output, /reality-opts:\n(?:[^\n]*\n)*?\s+support-x25519mlkem768: true/);
    assert.match(output, /public-key: "fixture-key"/);
    assert.match(output, /short-id: "0123456789abcdef"/);
    assert.match(output, /flow: "xtls-rprx-vision"/);
  }
});

test('non-REALITY and Hysteria2 outputs do not receive the REALITY flag', () => {
  const plain = { ...node, reality_public_key: '' };
  assert.doesNotMatch(sub.generateClashSubForUser([plain]), /support-x25519mlkem768/);
  assert.doesNotMatch(sub.generateClashHy2Sub([{name:'hy',host:'example.invalid',port:443,ss_password:'fixture'}]), /support-x25519mlkem768/);
});

test('03:00 rotation is not scheduled; unrelated schedules remain', () => {
  const source = fs.readFileSync(path.join(__dirname, '../src/app.js'), 'utf8');
  const schedules = Array.from(source.matchAll(/cron\.schedule\('([^']+)'/g), match => match[1]);
  assert.deepEqual(schedules, ['0 4 * * *', '0 2 * * *', '30 4 * * *', '40 4 * * *', '50 4 * * *']);
  assert.match(source, /Daily 03:00 auto-rotation disabled/);
});
