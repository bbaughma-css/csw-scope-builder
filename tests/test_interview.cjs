// test_interview.cjs
const { JSDOM } = require('jsdom');
const fs = require('fs');
const assert = require('assert');
const path = require('path');
const html = fs.readFileSync(process.argv[2] || path.join(__dirname, '..', 'interview.html'), 'utf8');
const samplePath = process.argv[3] || path.join(__dirname, 'sample-answers-v1.json');

function boot() {
  const dom = new JSDOM(html, { runScripts: 'dangerously', pretendToBeVisual: true });
  return new Promise(res => setTimeout(() => res(dom.window), 60));
}
function click(w, sel) { w.document.querySelector(sel).click(); }
function type(w, el, v) { el.value = v; el.dispatchEvent(new w.Event('input', { bubbles: true })); }

(async () => {
// 1. boots, no em dashes or curly quotes in file
assert(!/[\u2014\u2013\u2018\u2019\u201c\u201d\u2026]/.test(html), 'banned characters present');
let w = await boot();
const api = w.CSWInterview;
assert(api, 'api exposed');

// 2. empty form fails validation with many errors
let errs = api.validate();
assert(errs.length >= 8, 'empty form should fail: ' + errs.length);

// 3. scalar binding + conditional visibility
const rel = w.document.querySelector('[data-show-if="tenant.deployment=onprem"]');
assert(rel.hidden === true, 'release hidden by default');
click(w, 'input[name="tenant.deployment"][value="onprem"]');
assert(rel.hidden === false, 'release shown for onprem');
click(w, 'input[name="tenant.deployment"][value="saas"]');
assert(rel.hidden === true, 'release hidden for saas');
assert.strictEqual(api.getState().tenant.deployment, 'saas');
type(w, w.document.getElementById('c-name'), 'Acme: Corp/East');
type(w, w.document.getElementById('t-lic'), '500');
assert.strictEqual(api.getState().tenant.license_count, 500);
click(w, 'input[name="tenant.existing_tree"][value="false"]');
assert.strictEqual(api.getState().tenant.existing_tree, false);
click(w, 'input[name="tenant.kubernetes"][value="false"]');
click(w, 'input[data-set="label_sources.sources"][value="none"]');
assert.deepStrictEqual(Array.from(api.getState().label_sources.sources), ['none']);
click(w, 'input[name="access.separate_teams"][value="false"]');
click(w, 'input[name="compliance.has_zones"][value="false"]');

// 4. list editor: suggestion button, duplicate guard, remove
const envBox = w.document.querySelector('[data-list="structure.environments"]');
envBox.querySelector('.suggest button').click(); // Add Production
assert.deepStrictEqual(Array.from(api.getState().structure.environments), ['Production']);
let inp = w.document.querySelector('[data-list="structure.environments"] .addline input');
inp.value = 'production';
w.document.querySelector('[data-list="structure.environments"] .addline button').click();
assert.strictEqual(api.getState().structure.environments.length, 1, 'case-insensitive duplicate blocked');

// 5. paste import: tabs, header skip, auto-add env + location, subnets with commas
let n = api.importPasted('Application\tEnvironment\tOwner\tSite\tSubnets\nPayroll\tproduction\tFinance IT\tDallas DC\t10.20.30.0/24, 10.20.31.5\nWiki\tTest\t\t\t');
assert.strictEqual(n, 2);
let st = api.getState();
assert.strictEqual(st.applications[0].environment, 'Production', 'env matched case-insensitively');
assert.deepStrictEqual(Array.from(st.structure.environments), ['Production', 'Test']);
assert.strictEqual(st.structure.locations[0].name, 'Dallas DC');
n = api.importPasted('CRM,Production,Sales,Dallas DC,10.1.0.0/16,10.2.0.0/16');
assert.strictEqual(st.applications[2].subnets, '10.1.0.0/16, 10.2.0.0/16');
api.renderAll();

// 6. validation: Wiki has no subnets while records lack application field
errs = api.validate();
assert.strictEqual(errs.length, 0, 'blank subnets are allowed: ' + errs.join(' | '));
st.applications[1].subnets = '10.9.9.999';
errs = api.validate();
assert(errs.some(e => /not valid/.test(e) && /10\.9\.9\.999/.test(e)), 'bad subnet flagged');
st.applications[1].subnets = '10.9.9.0/24 2001:db8::/32';
errs = api.validate();
assert.strictEqual(errs.length, 0, 'should pass: ' + errs.join(' | '));

// duplicate app in same environment
st.applications.push({ name: 'payroll', environment: 'Production', owner: '', location: '', subnets: '10.0.0.1' });
assert(api.validate().some(e => /more than once/.test(e)));
st.applications.pop();

// stale environment
st.structure.environments.splice(1, 1);
assert(api.validate().some(e => /no longer listed/.test(e)));
st.structure.environments.push('Test');

// 7. table render: application rows exist with selects populated
api.renderAll();
const rows = w.document.querySelectorAll('[data-table="applications"] .row');
assert.strictEqual(rows.length, 3);
const envSel = rows[0].querySelectorAll('select')[0];
assert.strictEqual(envSel.value, 'Production');
// labels tied to controls
rows[0].querySelectorAll('label').forEach(l => assert(w.document.getElementById(l.getAttribute('for'))));

// 8. output + round trip into a fresh page
const out = api.buildOutput(true);
assert.strictEqual(out.schema, 'csw-scope-interview');
assert.strictEqual(out.schema_version, 4);
// section 6: every saved file carries the one product version, and the page shows it
assert.strictEqual(out.tool_version, '1.2'); assert.strictEqual(w.CSWInterview.TOOL_VERSION, '1.2');
assert(/CSW Scope Builder version 1\.2/.test(w.document.getElementById('tool-version').textContent));
assert.strictEqual(out.answers.tenant.build_under, '');
assert.strictEqual(out.complete, true);
const fn = api.fileName(true);
assert(/^\d{4}-\d{2}-\d{2} Acme CorpEast - CSW Scope Answers\.json$/.test(fn), fn);
const w2 = await boot();
assert.strictEqual(w2.CSWInterview.loadText(JSON.stringify(out)), '');
assert.strictEqual(w2.CSWInterview.validate().length, 0);
assert.strictEqual(w2.document.getElementById('c-name').value, 'Acme: Corp/East');
assert(w2.document.querySelector('input[name="tenant.deployment"][value="saas"]').checked);
assert.strictEqual(w2.document.querySelectorAll('[data-table="applications"] .row').length, 3);

// 9. bad files rejected
assert(w2.CSWInterview.loadText('not json') !== '');
assert(w2.CSWInterview.loadText('{"schema":"x"}') !== '');
assert(w2.CSWInterview.loadText(JSON.stringify({ schema: 'csw-scope-interview', schema_version: 99, answers: {} })) !== '');
assert(/too new for this page: it uses answers format 99 and this page understands up to 4/.test(w2.CSWInterview.loadText(JSON.stringify({ schema: 'csw-scope-interview', schema_version: 99, answers: {} }))));

// 10. teams/zones conditionals
click(w, 'input[name="access.separate_teams"][value="true"]');
assert(w.document.querySelector('[data-show-if="access.separate_teams=true"]').hidden === false);
assert(api.validate().some(e => /Section 6/.test(e)));
w.document.querySelector('[data-table="access.teams"] > button').click();
type(w, w.document.querySelector('[data-table="access.teams"] .row input[type=text]'), 'Network Security');
assert(api.validate().some(e => /Network Security/.test(e) && /divided/.test(e)), 'manages_by required');
const mb = w.document.querySelector('[data-table="access.teams"] .row select');
mb.value = 'site'; mb.dispatchEvent(new w.Event('change', { bubbles: true }));
assert.strictEqual(api.getState().access.teams[0].manages_by, 'site');
assert.strictEqual(api.validate().length, 0, api.validate().join(' | '));

// 13. exclusive "Nowhere reliable"
const none = w.document.querySelector('input[data-set="label_sources.sources"][value="none"]');
const ipam = w.document.querySelector('input[data-set="label_sources.sources"][value="ipam"]');
assert(none.checked);
ipam.click();
assert.deepStrictEqual(Array.from(api.getState().label_sources.sources), ['ipam']);
assert(!none.checked && ipam.checked);
none.click();
assert.deepStrictEqual(Array.from(api.getState().label_sources.sources), ['none']);
assert(none.checked && !ipam.checked);

// 14. zone column appears only when zones exist, and each zone needs an application
const appBox = w.document.querySelector('[data-table="applications"]');
const selCount = () => appBox.querySelector('.row').querySelectorAll('select').length;
assert.strictEqual(selCount(), 2, 'no zone column yet');
click(w, 'input[name="compliance.has_zones"][value="true"]');
w.document.querySelector('[data-table="compliance.zones"] > button').click();
const zin = w.document.querySelector('[data-table="compliance.zones"] .row input[type=text]');
type(w, zin, 'PCI'); zin.dispatchEvent(new w.Event('change', { bubbles: true }));
assert.strictEqual(selCount(), 3, 'zone column shown');
assert.strictEqual(api.validate().length, 0, 'a zone with no application yet is allowed');
const zsel = appBox.querySelector('.row').querySelectorAll('select')[2];
zsel.value = 'PCI'; zsel.dispatchEvent(new w.Event('change', { bubbles: true }));
assert.strictEqual(api.getState().applications[0].zone, 'PCI');
assert.strictEqual(api.validate().length, 0, api.validate().join(' | '));
api.getState().compliance.zones[0].name = 'HIPAA';
assert(api.validate().some(e => /no longer listed in section 7/.test(e)));
api.getState().compliance.zones[0].name = 'PCI';

// 15. misaligned subnet
api.getState().applications[0].subnets = '10.10.10.0/16, 10.20.10.0/24 10.1.1.1 0.0.0.0/0 192.168.1.130/25';
let me = api.validate();
assert.strictEqual(me.length, 1, me.join(' | '));
assert(/10\.10\.10\.0\/16 should be written 10\.10\.0\.0\/16/.test(me[0]) && /192\.168\.1\.130\/25 should be written 192\.168\.1\.128\/25/.test(me[0]) && !/10\.20\.10\.0\/24 should/.test(me[0]), me[0]);

// 16. The version 1 sample still loads, and the four gaps are now caught
const w4 = await boot();
assert.strictEqual(w4.CSWInterview.loadText(fs.readFileSync(samplePath, 'utf8')), '');
const se = w4.CSWInterview.validate();
assert.strictEqual(se.length, 4, se.join(' | '));
assert(se.some(e => /Nowhere reliable/.test(e)));
assert(se.some(e => /10\.10\.0\.0\/16/.test(e)));
assert.strictEqual(se.filter(e => /divided/.test(e)).length, 2);
assert.deepStrictEqual(JSON.parse(JSON.stringify(w4.CSWInterview.getState().structure.shared_services[0])), { name: 'DNS', subnets: '' });
assert.strictEqual(w4.document.querySelectorAll('[data-table="structure.shared_services"] .row').length, 6);

// 16b. parent scope question appears only when scopes already exist
const w6 = await boot();
const under = w6.document.getElementById('t-under');
assert.strictEqual(under.closest('.q').hidden, true);
click(w6, 'input[name="tenant.existing_tree"][value="true"]');
assert.strictEqual(under.closest('.q').hidden, false);
type(w6, under, 'Company:Internal:Lab');
assert.strictEqual(w6.CSWInterview.getState().tenant.build_under, 'Company:Internal:Lab');
assert(!w6.CSWInterview.validate().some(e => /under/.test(e)), 'optional');

// 17. shared services table, optional addresses, optional license count
const w5 = await boot();
const a5 = w5.CSWInterview;
const svcBox = w5.document.querySelector('[data-table="structure.shared_services"]');
svcBox.querySelector('.suggest button').click();
assert.strictEqual(a5.getState().structure.shared_services[0].name, 'DNS');
assert(!Array.from(svcBox.querySelectorAll('.suggest button')).some(b => b.textContent === 'Add DNS'), 'used suggestion disappears');
assert(!a5.validate().some(e => /shared service/.test(e)), 'addresses are optional');
a5.getState().structure.shared_services[0].subnets = '10.0.0.53, 10.0.0.9/24';
assert(a5.validate().some(e => /shared service 1 \(DNS\)/.test(e) && /10\.0\.0\.0\/24/.test(e)));
a5.getState().structure.shared_services[0].subnets = '10.0.0.53';
a5.getState().structure.shared_services.push({ name: 'dns', subnets: '' }, { name: '', subnets: '' });
let e5 = a5.validate();
assert(e5.some(e => /more than once/.test(e)) && e5.some(e => /enter a name or remove the row/.test(e)));
assert(!e5.some(e => /licenses/.test(e)), 'blank license count allowed');
assert(!e5.some(e => /at least one application/.test(e)), 'no applications is allowed');
a5.getState().tenant.license_count = 2.5;
assert(a5.validate().some(e => /whole number/.test(e)));
assert(w5.document.querySelector('[data-list="structure.shared_services"]') === null);
assert.strictEqual(w4.document.querySelectorAll('[data-table="applications"] .row').length, 3);

// 11. no network use in the page
assert(!/fetch\(|XMLHttpRequest|sendBeacon|<script[^>]+src=|<link[^>]+href=|localStorage|https?:\/\//.test(html), 'page must be self-contained');

// 12. finish button with errors shows the list and does not download
const w3 = await boot();
w3.document.getElementById('save-final').click();
assert(w3.document.getElementById('errors').hidden === false);
assert(w3.document.getElementById('status').hidden === true);

console.log('ALL PASS');
})().catch(e => { console.error(e.message, (e.stack||'').split('\n')[1]); process.exit(1); });
