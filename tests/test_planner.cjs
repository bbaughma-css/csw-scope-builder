// test_planner.cjs
const { JSDOM } = require('jsdom');
const fs = require('fs');
const assert = require('assert');
const path = require('path');
const nodePath = path;
const html = fs.readFileSync(process.argv[2] || path.join(__dirname, '..', 'planner.html'), 'utf8');
const sample = JSON.parse(fs.readFileSync(process.argv[3] || path.join(__dirname, 'sample-answers-v1.json'), 'utf8'));

function boot() {
  const dom = new JSDOM(html, { runScripts: 'dangerously', pretendToBeVisual: true });
  return new Promise(res => setTimeout(() => res(dom.window), 60));
}
const clone = o => JSON.parse(JSON.stringify(o));
const texts = (plan, level) => plan.findings.filter(f => f.level === level).map(f => f.text);

(async () => {
  assert(!/[\u2014\u2013\u2018\u2019\u201c\u201d\u2026]/.test(html), 'banned characters present');
  assert(!/fetch\(|XMLHttpRequest|sendBeacon|<script[^>]+src=|<link[^>]+href=|localStorage/.test(html), 'page must be self-contained');
  const w = await boot();
  const P = w.CSWPlanner;
  const B = (d, e, o) => clone(P.buildPlan(d, e, o));

  // token parsing
  assert.strictEqual(P.parseToken('10.10.10.0/16').aligned, false);
  assert.strictEqual(P.parseToken('10.10.10.0/16').fixed, '10.10.0.0/16');
  assert.strictEqual(P.parseToken('10.20.10.0/24').aligned, true);
  assert.strictEqual(P.parseToken('300.1.1.1'), null);
  assert.strictEqual(P.parseToken('10.1.1.1/33'), null);
  assert.strictEqual(P.parseToken('0.0.0.0/0').end, 4294967295);
  assert.strictEqual(P.parseToken('2001:db8::/32').v, 6);

  // 1. the acme sample (a version 1 answers file)
  let plan = B(clone(sample), null);
  assert.deepStrictEqual(Array.from(plan.layers), ['Environment', 'Application']);
  assert.strictEqual(plan.scopes.length, 12, 'acme should give 12 scopes, got ' + plan.scopes.length);
  assert.deepStrictEqual(plan.scopes.filter(s => s.depth === 1).map(s => s.short_name), ['Production', 'Non-Production', 'Shared']);
  assert.strictEqual(plan.scopes.filter(s => s.parent_ref === plan.scopes.find(x => x.short_name === 'Shared').ref).length, 6);
  // parents always come before children
  const pos = {}; plan.scopes.forEach((s, i) => pos[s.ref] = i);
  plan.scopes.forEach(s => assert(s.parent_ref === 'root' || pos[s.parent_ref] < pos[s.ref]));
  let b = texts(plan, 'blocker');
  assert.strictEqual(b.length, 1, b.join(' | '));
  assert(/10\.10\.10\.0\/16/.test(b[0]) && /10\.10\.0\.0\/16/.test(b[0]));
  assert.strictEqual(plan.ready, false);
  let r = texts(plan, 'review');
  assert(r.some(t => /Nowhere reliable/.test(t)));
  let l = texts(plan, 'later');
  assert.strictEqual(l.filter(t => /has not said how its responsibility/.test(t)).length, 2);
  assert(l.some(t => /zone 1/.test(t)));
  assert(l.some(t => /shared services have no addresses yet: DNS, Active Directory, Backup, NTP, Monitoring, Patch Management/.test(t)));
  assert.strictEqual(r.length, 1, r.join(' | '));
  assert(plan.todo[plan.todo.length - 1].startsWith('For the next round'));
  assert.strictEqual(plan.label_rows.length, 1);
  assert.deepStrictEqual(Array.from(plan.label_columns), ['IP', 'Environment', 'Application', 'Location']);
  assert.strictEqual(P.labelCsv(plan), 'IP,Environment,Application,Location\r\n10.20.10.0/24,Production,test,washington\r\n');
  assert(plan.todo.some(t => /payroll \(Non-Production\)/.test(t)));
  assert(plan.todo[0].startsWith('Resolve the blockers'));
  const lim = Object.fromEntries(plan.checks.map(c => [c.name, c]));
  assert.strictEqual(lim['Child scopes in the tenant'].value, 12);
  assert.strictEqual(lim['Labeled addresses in the label file (SaaS)'].limit, 30000);
  assert.strictEqual(lim['Labeled subnets in the label file (SaaS)'].limit, 600);
  assert.strictEqual(lim['Most child scopes under one parent'].value, 6);
  assert.strictEqual(lim['Levels below the top-level scope'].value, 2);

  // 2. corrected sample is ready
  let fixed = clone(sample);
  fixed.answers.applications[0].subnets = '10.10.0.0/16';
  plan = B(fixed, null);
  assert.strictEqual(plan.ready, true, texts(plan, 'blocker').join(' | '));
  assert.strictEqual(plan.label_rows.length, 2);

  // 3. site level and zone level
  let v2 = clone(fixed);
  v2.schema_version = 2;
  v2.answers.access.teams = [{ name: 'DC Ops', manages_by: 'site', manages: '' }];
  v2.answers.compliance.zones = [{ name: 'PCI', separate_team: true }];
  v2.answers.applications[0].zone = 'PCI';
  plan = B(v2, null);
  assert.deepStrictEqual(Array.from(plan.layers), ['Environment', 'Location', 'Zone', 'Application']);
  const path = name => { const out = []; let s = plan.scopes.find(x => x.short_name === name && x.label === 'Application'); while (s) { out.unshift(s.label + '=' + s.value); s = plan.scopes.find(x => x.ref === s.parent_ref); } return out.join(' > '); };
  assert.strictEqual(path('one two three four'), 'Environment=Production > Location=boston > Zone=PCI > Application=one two three four');
  assert.strictEqual(path('test'), 'Environment=Production > Location=washington > Zone=Unregulated > Application=test');
  assert.strictEqual(path('DNS'), 'Environment=Shared > Application=DNS');
  assert.strictEqual(Math.max(...plan.scopes.map(s => s.depth)), 4);
  assert.strictEqual(plan.ready, true, texts(plan, 'blocker').join(' | '));
  assert.deepStrictEqual(Array.from(plan.label_columns), ['IP', 'Environment', 'Application', 'Location', 'Zone']);
  assert(P.labelCsv(plan).includes('10.20.10.0/24,Production,test,washington,Unregulated'));
  // one label per sibling group
  const groups = {}; plan.scopes.forEach(s => (groups[s.parent_ref] = groups[s.parent_ref] || new Set()).add(s.label));
  Object.values(groups).forEach(g => assert.strictEqual(g.size, 1, 'siblings must share one label'));
  // application with no site is blocked when a Location level exists
  let nosite = clone(v2); nosite.answers.applications[2].location = '';
  plan = B(nosite, null);
  assert(texts(plan, 'later').some(t => /payroll/.test(t) && /Location level/.test(t)));
  assert.strictEqual(plan.ready, true);
  assert(!plan.scopes.some(s => s.short_name === 'payroll'), 'left out of this round');

  // 4. address conflicts
  let dup = clone(fixed);
  dup.answers.applications[1].subnets = '10.10.0.0/16';
  plan = B(dup, null);
  assert(texts(plan, 'blocker').some(t => /listed for both/.test(t) && /left out of the label file/.test(t)));
  assert.strictEqual(plan.label_rows.length, 0, 'a subnet claimed twice is in no label row');
  assert(plan.todo.some(t => /--under "the full name of the scope to build under"/.test(t)) || !plan.todo.some(t => /--under/.test(t)));
  assert(B(fixed, null).todo.some(t => /apply --plan/.test(t) && /--under "the full name of the scope to build under"/.test(t)));
  // a real run: three shared-service pairs on one subnet each
  let wc = clone(fixed); wc.schema_version = 3;
  wc.answers.structure.shared_services = [{ name: 'Customer', subnets: '10.99.1.0/24' }, { name: 'DNS', subnets: '10.0.0.0/16' }, { name: 'NTP', subnets: '10.0.0.0/16' }, { name: 'Patch Management', subnets: '10.30.0.0/16' }];
  plan = B(wc, null);
  assert.strictEqual(texts(plan, 'blocker').length, 1);
  assert.deepStrictEqual(plan.label_rows.filter(r => r.Environment === 'Shared').map(r => r.Application), ['Customer', 'Patch Management']);
  let ov = clone(fixed);
  ov.answers.applications[1].subnets = '10.10.5.0/24, 10.10.5.0/24';
  plan = B(ov, null);
  assert(texts(plan, 'review').some(t => /overlaps/.test(t)));
  assert.strictEqual(plan.label_rows.length, 2, 'repeat inside one application is dropped');
  let bad = clone(fixed); bad.answers.applications[1].subnets = 'banana';
  assert(texts(B(bad, null), 'blocker').some(t => /banana/.test(t)));

  // 5. no subnets and no application field in records
  let norec = clone(fixed); norec.answers.label_sources.fields = ['owner'];
  plan = B(norec, null);
  assert(texts(plan, 'later').some(t => /payroll/.test(t) && /stays empty/.test(t)));
  assert.strictEqual(plan.ready, true, 'missing knowledge does not block');
  assert(plan.scopes.some(s => s.short_name === 'payroll'));
  assert(plan.todo.some(t => /add them to your answers for the next round: payroll/.test(t)));

  // 5b. version 3 answers: shared services with optional addresses, blank license count, no applications
  let v3 = clone(fixed); v3.schema_version = 3;
  v3.answers.structure.shared_services = [{ name: 'DNS', subnets: '10.0.0.53 10.0.1.0/28' }, { name: 'NTP', subnets: '' }];
  v3.answers.tenant.license_count = '';
  plan = B(v3, null);
  assert.strictEqual(plan.ready, true, texts(plan, 'blocker').join(' | '));
  assert(P.labelCsv(plan).includes('10.0.0.53,Shared,DNS,\r\n') && P.labelCsv(plan).includes('10.0.1.0/28,Shared,DNS,'));
  assert.strictEqual(plan.label_rows.length, 4);
  assert(texts(plan, 'later').some(t => /no addresses yet: NTP\./.test(t)));
  assert(texts(plan, 'later').some(t => /license count was not given/.test(t)));
  assert.strictEqual(plan.checks.filter(c => c.result === 'not checked').length, 2);
  assert(plan.todo.some(t => /shared services run/.test(t) && /: NTP\./.test(t)));
  v3.answers.structure.shared_services[0].subnets = '10.20.10.0/24';
  assert(texts(B(v3, null), 'blocker').some(t => /listed for both test \(Production\) and DNS \(Shared\)/.test(t)));
  let envonly = clone(fixed); envonly.answers.applications = []; envonly.answers.structure.shared_services = [];
  plan = B(envonly, null);
  assert.strictEqual(plan.ready, true);
  assert.deepStrictEqual(plan.scopes.map(s => s.short_name), ['Production', 'Non-Production']);
  assert.strictEqual(texts(plan, 'later').filter(t => /no applications listed yet/.test(t)).length, 2);

  // 6. file-level blockers
  let draft = clone(fixed); draft.complete = false;
  assert(texts(B(draft, null), 'blocker').some(t => /in progress/.test(t)));
  let old = clone(fixed); old.answers.tenant.deployment = 'onprem'; old.answers.tenant.release = 'older';
  plan = B(old, null);
  assert(texts(plan, 'blocker').some(t => /older than 3\.10/.test(t)));
  assert(plan.checks.some(c => c.result === 'not checked'));
  let ex = clone(fixed); ex.answers.tenant.existing_tree = true;
  assert(texts(B(ex, null), 'blocker').some(t => /no existing scope list/.test(t)));

  // 7. SaaS label limit
  let small = clone(fixed); small.answers.tenant.license_count = 1;
  plan = B(small, null);
  assert(texts(plan, 'blocker').some(t => /Labeled subnets/.test(t) && /over the limit of 1\b/.test(t)), texts(plan, 'blocker').join(' | '));

  // 8. scope count limit
  let big = clone(fixed);
  big.answers.applications = Array.from({ length: 1001 }, (_, i) => ({ name: 'app' + i, environment: 'Production', owner: '', location: '', subnets: '' }));
  plan = B(big, null);
  b = texts(plan, 'blocker');
  assert(b.some(t => /Child scopes in the tenant/.test(t)) && b.some(t => /Most child scopes under one parent/.test(t)), b.join(' | '));

  // 9. existing tree: additions only, conflicts flagged
  const existing = [
    { id: 'r1', short_name: 'AcmeRoot', name: 'AcmeRoot', parent_app_scope_id: null, short_query: { type: 'subnet', field: 'ip', value: '0.0.0.0/0' } },
    { id: 'e1', short_name: 'production', name: 'AcmeRoot:production', parent_app_scope_id: 'r1', short_query: { type: 'eq', field: 'user_Environment', value: 'Production' } },
    { id: 'a1', short_name: 'Test', name: 'AcmeRoot:production:Test', parent_app_scope_id: 'e1', short_query: { type: 'subnet', field: 'ip', value: '10.20.10.0/24' } },
    { id: 'l1', short_name: 'Legacy', name: 'AcmeRoot:Legacy', parent_app_scope_id: 'r1', short_query: { type: 'subnet', field: 'ip', value: '172.16.0.0/12' } }
  ];
  ex = clone(fixed); ex.answers.tenant.existing_tree = true;
  plan = B(ex, existing);
  assert.strictEqual(plan.root.short_name, 'AcmeRoot');
  assert.strictEqual(plan.root.existing_id, 'r1');
  const st = Object.fromEntries(plan.scopes.map(s => [s.short_name, s.status]));
  assert.strictEqual(st['Production'], 'exists');
  assert.strictEqual(st['test'], 'conflict');
  assert.strictEqual(st['one two three four'], 'create');
  assert.strictEqual(st['Non-Production'], 'create');
  assert.strictEqual(plan.scopes.filter(s => s.status === 'create').length, 10);
  r = texts(plan, 'review');
  assert(r.some(t => /already exists with a different query/.test(t) && /10\.20\.10\.0\/24/.test(t)));
  assert(r.some(t => /not part of this plan: Legacy/.test(t)));
  assert.strictEqual(plan.checks[0].value, 13, 'three existing plus ten new');
  assert(plan.todo.some(t => /Create the 10 new scopes/.test(t)));
  assert.strictEqual(plan.ready, true, texts(plan, 'blocker').join(' | '));

  // 9b. real export shape from a lab: a sub-scope of a shared tenant, queries by address
  const lab = { schema: 'csw-scope-export', schema_version: 1, partial: true, under: 'tenant:Internal:Labs:team-a', scopes: [
    {"id":"x0","short_name":"team-a","parent_app_scope_id":"x1","short_query":{"type":"eq","field":"user_Team","value":"team-a"}},
    {"id":"x2","short_name":"SiteB","parent_app_scope_id":"x0","short_query":{"type":"subnet","field":"ip","value":"10.99.60.0/24"}},
    {"id":"x3","short_name":"SiteA","parent_app_scope_id":"x0","short_query":{"type":"or","filters":[{"type":"subnet","field":"ip","value":"10.99.1.0/24"},{"type":"subnet","field":"ip","value":"10.99.10.0/24"}]}},
    {"id":"x4","short_name":"Shop","parent_app_scope_id":"x2","short_query":{"type":"or","filters":[{"type":"eq","field":"ip","value":"10.99.60.71"},{"type":"eq","field":"ip","value":"10.99.60.72"},{"type":"eq","field":"ip","value":"10.99.60.73"}]}},
    {"id":"x5","short_name":"Core-Infra","parent_app_scope_id":"x2","short_query":{"type":"or","filters":[{"type":"eq","field":"ip","value":"10.99.60.10"},{"type":"eq","field":"ip","value":"10.99.60.60"}]}},
    {"id":"x6","short_name":"Endpoints","parent_app_scope_id":"x2","short_query":{"type":"or","filters":[{"type":"eq","field":"ip","value":"10.99.60.20"},{"type":"eq","field":"ip","value":"10.99.60.30"}]}},
    {"id":"x7","short_name":"Infrastructure","parent_app_scope_id":"x3","short_query":{"type":"or","filters":[{"type":"eq","field":"ip","value":"10.99.1.1"},{"type":"eq","field":"ip","value":"10.99.1.50"}]}},
    {"id":"x8","short_name":"Edge","parent_app_scope_id":"x3","short_query":{"type":"eq","field":"ip","value":"10.99.1.60"}},
    {"id":"x9","short_name":"Web","parent_app_scope_id":"x4","short_query":{"type":"and","filters":[{"type":"eq","field":"ip","value":"10.99.60.71"},{"type":"eq","field":"user_Tier","value":"Web"}]}},
    {"id":"x10","short_name":"App","parent_app_scope_id":"x4","short_query":{"type":"eq","field":"ip","value":"10.99.60.72"}},
    {"id":"x11","short_name":"DB","parent_app_scope_id":"x4","short_query":{"type":"eq","field":"ip","value":"10.99.60.73"}}
  ] };
  plan = B(ex, lab.scopes, { partial: true });
  assert.strictEqual(plan.root.short_name, 'team-a');
  assert.strictEqual(plan.root.existing_id, 'x0');
  assert.strictEqual(plan.source.existing_scope_count, 11);
  assert.strictEqual(plan.source.existing_partial, true);
  assert.strictEqual(plan.scopes.filter(s => s.status === 'create').length, 12);
  assert.strictEqual(plan.checks[0].value, 23);
  assert(/only part of the tenant/.test(plan.checks[0].note));
  // whole-tenant count and label names carried by the export file
  let full = B(ex, lab.scopes, { partial: true, tenantChildCount: 74, labelColumns: ['Application', 'Location', 'Organization', 'Owner', 'PCI', 'Services', 'Tier', 'VRF', 'Workload Type'] });
  assert.strictEqual(full.checks[0].value, 86);
  assert(!/only part/.test(full.checks[0].note));
  // D18: an export from helper 1.5 carries only tenant_scope_count. The subtract-one shortcut is gone, so it is treated as a partial count
  let oldExport = B(ex, lab.scopes, { partial: true, tenantScopeCount: 75 });
  assert.strictEqual(oldExport.checks[0].value, 23); assert(/only part of the tenant/.test(oldExport.checks[0].note));
  const lc = full.checks.find(c => c.name === 'Label names in the tenant after upload');
  assert.strictEqual(lc.value, 10); assert.strictEqual(lc.result, 'pass'); assert.strictEqual(lc.note, 'Adds: Environment');
  assert(texts(full, 'review').some(t => /already uses the label names Application, Location/.test(t) && /check-labels/.test(t)));
  assert(full.todo.some(t => /check-labels --labels/.test(t) && /--under "team-a"/.test(t)));
  assert(full.todo.some(t => /apply --plan/.test(t) && /--write/.test(t)));
  let many = B(ex, lab.scopes, { labelColumns: Array.from({ length: 32 }, (_, i) => 'c' + i) });
  assert(texts(many, 'blocker').some(t => /Label names in the tenant after upload: 35 is over the limit of 32/.test(t)), texts(many, 'blocker').join(' | '));
  // build under any scope in the export
  let pick = B(ex, lab.scopes, { rootId: 'x2' });
  assert.strictEqual(pick.root.short_name, 'SiteB'); assert.strictEqual(pick.root.existing_id, 'x2');
  assert(texts(pick, 'review').some(t => /Under "SiteB" these existing scopes are not part of this plan: Shop, Core-Infra, Endpoints/.test(t)));
  assert.strictEqual(pick.scopes.filter(s => s.status === 'create').length, 12);
  assert(texts(plan, 'review').some(t => /Under "team-a" these existing scopes are not part of this plan: SiteB, SiteA/.test(t)));
  assert.strictEqual(plan.ready, true, texts(plan, 'blocker').join(' | '));
  assert.deepStrictEqual(plan.scopes[0].short_query, { type: 'eq', field: 'user_Environment', value: 'Production' });
  // second round: the scopes this plan creates would come back like this and must match as existing
  const round2 = lab.scopes.concat(plan.scopes.map(s => ({ id: 'n' + s.ref, short_name: s.short_name, parent_app_scope_id: s.parent_ref === 'root' ? 'x0' : 'n' + s.parent_ref, short_query: s.short_query })));
  let p2 = B(ex, round2, { partial: true });
  assert.strictEqual(p2.scopes.filter(s => s.status === 'exists').length, 12);
  assert.strictEqual(p2.scopes.filter(s => s.status === 'create').length, 0);
  let more = clone(ex); more.answers.applications.push({ name: 'billing', environment: 'Production', owner: '', location: '', subnets: '10.30.0.0/24' });
  p2 = B(more, round2, { partial: true });
  assert.deepStrictEqual(p2.scopes.filter(s => s.status === 'create').map(s => s.short_name), ['billing']);
  assert(p2.todo.some(t => /Create the 1 new scope in the order/.test(t)));
  assert.strictEqual(P.loadExisting(Object.assign({ tenant_scope_count: 75, tenant_child_scope_count: 74, label_columns: ['Application'] }, lab)), '');
  const rs = w.document.getElementById('root-sel');
  assert.strictEqual(rs.options.length, 11); assert.strictEqual(w.document.getElementById('root-pick').hidden, false);
  assert.strictEqual(rs.value, 'x0');
  P.loadAnswers(clone(ex)); P.rebuild();
  assert.strictEqual(P.getPlan().root.short_name, 'team-a'); assert.strictEqual(P.getPlan().checks[0].value, 86);
  rs.value = 'x3'; rs.dispatchEvent(new w.Event('change'));
  assert.strictEqual(P.getPlan().root.short_name, 'SiteA');
  // picker follows the customer's answer until someone picks by hand
  const namedLab = lab.scopes.map(x => Object.assign({ name: 'T:Internal:' + (x.id === 'x0' ? 'team-a' : 'team-a:' + x.short_name) }, x));
  P.loadExisting(Object.assign({}, lab, { scopes: namedLab }));
  let ask2 = clone(ex); ask2.answers.tenant.build_under = 'T:Internal:team-a:SiteB';
  P.loadAnswers(ask2); P.rebuild();
  assert.strictEqual(rs.value, 'x2'); assert.strictEqual(P.getPlan().root.existing_id, 'x2');
  assert(/Parent scope: T:Internal:team-a:SiteB/.test(w.document.getElementById('parent-line').textContent));
  rs.value = 'x3'; rs.dispatchEvent(new w.Event('change'));
  assert.strictEqual(P.getPlan().root.existing_id, 'x3');
  P.loadExisting(lab); P.loadAnswers(clone(ex)); P.rebuild();
  const lnE = w.document.getElementById('ln-Environment');
  lnE.value = 'Stage'; lnE.dispatchEvent(new w.Event('input'));
  assert.strictEqual(P.getPlan().scopes[0].short_query.field, 'user_Stage');
  lnE.value = 'Environment'; lnE.dispatchEvent(new w.Event('input'));

  // 9d. the customer names the parent scope in the questionnaire
  const named9 = lab.scopes.map(x => Object.assign({ name: 'T:Internal:' + (x.id === 'x0' ? 'team-a' : 'team-a:' + x.short_name) }, x));
  let ask = clone(ex); ask.schema_version = 4; ask.answers.tenant.build_under = 'T:Internal:team-a:SiteB';
  plan = B(ask, named9, {});
  assert.strictEqual(plan.root.existing_id, 'x2'); assert.strictEqual(plan.root.name, 'T:Internal:team-a:SiteB');
  assert(!texts(plan, 'review').some(t => /asked to build under|did not say which scope/.test(t)));
  assert(plan.todo.some(t => /--under "T:Internal:team-a:SiteB"/.test(t)));
  plan = B(ask, named9, { rootId: 'x3' });
  assert.strictEqual(plan.root.existing_id, 'x3');
  assert(texts(plan, 'review').some(t => /asked to build under "T:Internal:team-a:SiteB", but this plan builds under "T:Internal:team-a:SiteA"/.test(t)));
  ask.answers.tenant.build_under = 'Nope:Nothing';
  plan = B(ask, named9, {});
  assert.strictEqual(plan.root.existing_id, 'x0');
  assert(texts(plan, 'review').some(t => /no single scope with that name/.test(t)));
  ask.answers.tenant.build_under = 'siteb';
  assert.strictEqual(B(ask, named9, {}).root.existing_id, 'x2', 'unique short name works');
  ask.answers.tenant.build_under = '';
  assert(texts(B(ask, named9, {}), 'review').some(t => /did not say which scope to build under/.test(t) && /T:Internal:team-a/.test(t)));

  // 9c. label names can be changed, and bad names are blocked
  let named = B(fixed, null, { labelNames: { Environment: 'SB Env', Application: 'App_Name', Location: ' ', Zone: 'Zone' } });
  assert.strictEqual(named.ready, true, texts(named, 'blocker').join(' | '));
  assert.deepStrictEqual(named.label_names, { Environment: 'SB Env', Application: 'App_Name', Location: 'Location', Zone: 'Zone' });
  assert.deepStrictEqual(named.scopes[0].short_query, { type: 'eq', field: 'user_SB Env', value: 'Production' });
  assert.strictEqual(named.scopes.find(s => s.short_name === 'DNS').short_query.field, 'user_App_Name');
  assert.deepStrictEqual(named.label_columns, ['IP', 'SB Env', 'App_Name', 'Location']);
  assert.deepStrictEqual(named.label_rows[1], { IP: '10.20.10.0/24', 'SB Env': 'Production', App_Name: 'test', Location: 'washington' });
  assert.deepStrictEqual(named.layers, ['SB Env', 'App_Name']);
  assert.deepStrictEqual(named.labels.map(l => l.key), ['SB Env', 'App_Name', 'Location']);
  assert(named.labels[0].values.includes('Shared') && named.labels[1].values.includes('DNS'));
  const bn = n => texts(B(fixed, null, { labelNames: n }), 'blocker');
  assert(bn({ Environment: 'orchestrator_env' }).some(t => /reserves/.test(t)));
  assert(bn({ Environment: 'user_Env' }).some(t => /reserves/.test(t)));
  assert(bn({ Application: 'IP' }).some(t => /reserved by Secure Workload/.test(t)));
  assert(bn({ Application: 'a,b' }).some(t => /not usable/.test(t)));
  assert(bn({ Application: 'environment' }).some(t => /Two label names are the same/.test(t)));
  assert.strictEqual(bn({}).length, 0);
  // a renamed label no longer collides with the tenant's own, and near-matches are flagged
  let ren = B(ex, lab.scopes, { labelColumns: ['Application', 'Location', 'Owner'], labelNames: { Application: 'SB_Application', Location: 'SB_Location' } });
  assert(!texts(ren, 'review').some(t => /already uses the label names/.test(t)));
  assert.strictEqual(ren.checks.find(c => /Label names/.test(c.name)).note, 'Adds: Environment, SB_Application, SB_Location');
  let cap = B(ex, lab.scopes, { labelColumns: ['application'] });
  assert(texts(cap, 'review').some(t => /only by capitalization/.test(t)));
  // round two matches only when the same names are used
  const r2named = lab.scopes.concat(named.scopes.map(s => ({ id: 'm' + s.ref, short_name: s.short_name, parent_app_scope_id: s.parent_ref === 'root' ? 'x0' : 'm' + s.parent_ref, short_query: s.short_query })));
  assert.strictEqual(B(ex, r2named, { labelNames: named.label_names }).scopes.filter(s => s.status === 'exists').length, 12);
  assert.strictEqual(B(ex, r2named, {}).scopes.filter(s => s.status === 'conflict').length, 12);

  // ---------- Phase 1 (release 1.1) ----------
  // shared rule tables: the helper test reads the same file, so the two cannot drift apart
  const RULES = JSON.parse(fs.readFileSync(nodePath.join(__dirname, 'rules.json'), 'utf8'));
  RULES.comparison.forEach(c => {
    assert.deepStrictEqual(Array.from(P.sameQuery(c.a, c.b)), [c.same, c.exact], JSON.stringify(c));
    assert.deepStrictEqual(Array.from(P.sameQuery(c.b, c.a)), [c.same, c.exact], JSON.stringify(c));
  });
  RULES.names.forEach(c => assert.deepStrictEqual(Array.from(P.sameName(c.a, c.b)), [c.same, c.exact], JSON.stringify(c)));
  RULES.file_names.forEach(c => assert.strictEqual(P.safeName(c.in), c.out, JSON.stringify(c)));
  assert.strictEqual(P.planFingerprint(RULES.fingerprint.scopes), RULES.fingerprint.sha256);
  assert.strictEqual(P.planFingerprint(RULES.fingerprint.scopes.slice().reverse()), RULES.fingerprint.sha256);
  assert.strictEqual(P.sha256Hex(''), 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  assert.strictEqual(P.sha256Hex('abc'), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  assert.strictEqual(P.sha256Hex('a'.repeat(200)), require('crypto').createHash('sha256').update('a'.repeat(200)).digest('hex'));
  assert.strictEqual(P.sha256Hex('Café 東京'), require('crypto').createHash('sha256').update('Café 東京', 'utf8').digest('hex'));
  assert.strictEqual(B(fixed, null).fingerprint, P.planFingerprint(B(fixed, null).scopes));
  assert.strictEqual(P.TOOL_VERSION, '1.2');

  // 7.1 build from any level. The D1 case: parent Acme:Production, answers with Production and Development
  const d1 = clone(fixed); d1.answers.tenant.existing_tree = true;
  d1.answers.structure.environments = ['Production', 'Development'];
  d1.answers.structure.locations = [{ name: 'Dallas', type: 'datacenter' }, { name: 'Austin', type: 'datacenter' }];
  d1.answers.applications = [
    { name: 'Payroll', environment: 'Production', owner: '', location: 'Dallas', subnets: '10.1.0.0/24' },
    { name: 'HR', environment: 'production', owner: '', location: 'Austin', subnets: '' },
    { name: 'Sandbox', environment: 'Development', owner: '', location: 'Dallas', subnets: '10.2.0.0/24' }];
  d1.answers.structure.shared_services = [{ name: 'DNS', subnets: '10.0.0.53' }];
  d1.answers.compliance = { has_zones: false, zones: [] }; d1.answers.access = { separate_teams: false, teams: [] };
  const eq = (label, value) => ({ type: 'eq', field: 'user_' + label, value });
  const acme = [
    { id: 'a0', short_name: 'Acme', name: 'Acme', parent_app_scope_id: null, short_query: { type: 'subnet', field: 'ip', value: '0.0.0.0/0' } },
    { id: 'a1', short_name: 'Production', name: 'Acme:Production', parent_app_scope_id: 'a0', short_query: eq('Environment', 'Production') },
    { id: 'a2', short_name: 'Payroll', name: 'Acme:Production:Payroll', parent_app_scope_id: 'a1', short_query: eq('Application', 'Payroll') }];
  const names1 = pl => pl.scopes.filter(s => s.status !== 'outside').map(s => (s.parent_ref === 'root' ? '' : pl.scopes.find(x => x.ref === s.parent_ref).short_name + '>') + s.short_name + ':' + s.status);
  // a proposed anchor is never applied by itself: the plan is blocked until it is confirmed or cleared
  plan = B(d1, acme, { rootId: 'a1' });
  assert(texts(plan, 'blocker').some(t => /Confirm or clear what the parent scope stands for/.test(t) && /Environment = Production \(from the query of "Acme:Production"\)/.test(t)), texts(plan, 'blocker').join(' | '));
  assert.strictEqual(plan.ready, false); assert.deepStrictEqual(plan.anchors, []);
  assert(names1(plan).includes('Production:create'), 'still the 1.0 layout until confirmed');
  let rows = P.buildPlan(clone(d1), acme, { rootId: 'a1' }).ui.anchorRows;
  assert.deepStrictEqual(Array.from(rows, r => r.level + ':' + r.state + ':' + r.value), ['Environment:pending:Production', 'Location:none:', 'Zone:none:', 'Application:none:']);
  assert.strictEqual(rows[0].proposed.source, 'query'); assert.deepStrictEqual(Array.from(rows[0].options), ['Production', 'Development', 'Shared']);
  // confirmed: Payroll and HR directly under the parent, no Production, Development, or Shared scope, existing Payroll matched
  plan = B(d1, acme, { rootId: 'a1', anchors: { Environment: { value: 'production', confirmed: true } } });
  assert.strictEqual(plan.ready, true, texts(plan, 'blocker').join(' | '));
  assert.deepStrictEqual(names1(plan), ['Payroll:exists', 'HR:create']);
  assert.strictEqual(plan.scopes[0].existing_id, 'a2');
  assert.deepStrictEqual(plan.anchors, [{ scope_id: 'a1', scope_name: 'Acme:Production', level: 'Environment', value: 'Production', source: 'query' }]);
  assert.deepStrictEqual(plan.layers, ['Environment', 'Application']);
  assert(texts(plan, 'review').some(t => t === 'These are outside the chosen parent and are not in this plan: Sandbox (Development), DNS (Shared).'), texts(plan, 'review').join(' | '));
  // the label file still carries every label for what is in the plan, including the anchored one
  assert.deepStrictEqual(plan.label_rows, [{ IP: '10.1.0.0/24', Environment: 'Production', Application: 'Payroll', Location: 'Dallas' }]);
  assert.strictEqual(plan.schema_version, 3);
  // cleared: behaves as 1.0, with no blocker about anchors
  plan = B(d1, acme, { rootId: 'a1', anchors: { Environment: { value: '', confirmed: true } } });
  assert(!texts(plan, 'blocker').some(t => /Confirm or clear/.test(t))); assert(names1(plan).includes('Production:create')); assert.deepStrictEqual(plan.anchors, []);
  assert.strictEqual(P.buildPlan(clone(d1), acme, { rootId: 'a1', anchors: { Environment: { value: '' } } }).ui.anchorRows[0].state, 'cleared');
  // with no anchors and the top as the parent, the plan is exactly the 1.0 plan
  plan = B(d1, acme, { rootId: 'a0' });
  assert.deepStrictEqual(names1(plan), ['Production:exists', 'Development:create', 'Shared:create', 'Production>Payroll:exists', 'Production>HR:create', 'Development>Sandbox:create', 'Shared>DNS:create']);
  assert.deepStrictEqual(plan.anchors, []); assert.strictEqual(plan.ready, true);
  // a value the answers do not have cannot be an anchor
  assert(texts(B(d1, acme, { rootId: 'a1', anchors: { Environment: { value: 'Nope' } } }), 'blocker').some(t => /"Nope" is not a known environment/.test(t)));
  // parent anchored by name only (its query is a subnet) is proposed with source "name"
  const byName = clone(acme); byName[1].short_query = { type: 'subnet', field: 'ip', value: '10.0.0.0/8' };
  rows = P.buildPlan(clone(d1), byName, { rootId: 'a1' }).ui.anchorRows;
  assert.strictEqual(rows[0].state, 'pending'); assert.strictEqual(rows[0].proposed.source, 'name'); assert.strictEqual(rows[0].proposed.scope_name, 'Acme:Production');
  assert(texts(B(d1, byName, { rootId: 'a1' }), 'blocker').some(t => /from the name of "Acme:Production"/.test(t)));
  plan = B(d1, byName, { rootId: 'a1', anchors: { Environment: { value: 'Production' } } });
  assert.strictEqual(plan.anchors[0].source, 'name'); assert.deepStrictEqual(names1(plan), ['Payroll:conflict', 'HR:create'].map(x => x.replace('conflict', 'exists')));
  // a parent whose name matches values in two levels is not proposed, and a Review finding asks the consultant to choose
  const twoLevels = clone(d1); twoLevels.answers.applications.push({ name: 'production', environment: 'Development', owner: '', location: '', subnets: '' });
  plan = B(twoLevels, byName, { rootId: 'a1' });
  assert(!texts(plan, 'blocker').some(t => /Confirm or clear/.test(t)));
  assert(texts(plan, 'review').some(t => /"Acme:Production" has the same name as a value in more than one level \(Environment and Application\)/.test(t)), texts(plan, 'review').join(' | '));
  assert(P.buildPlan(clone(twoLevels), byName, { rootId: 'a1' }).ui.anchorRows.every(r => r.state === 'none'));
  // a two-level anchor: parent Acme:Production:Dallas with Environment and Location anchored
  const dallas = acme.concat([{ id: 'a3', short_name: 'Dallas', name: 'Acme:Production:Dallas', parent_app_scope_id: 'a1', short_query: eq('Location', 'dallas') }]);
  rows = P.buildPlan(clone(d1), dallas, { rootId: 'a3' }).ui.anchorRows;
  assert.deepStrictEqual(Array.from(rows, r => r.level + ':' + r.state + ':' + r.value), ['Environment:pending:Production', 'Location:pending:Dallas', 'Zone:none:', 'Application:none:']);
  plan = B(d1, dallas, { rootId: 'a3', anchors: { Environment: { value: 'Production' }, Location: { value: 'Dallas' } } });
  assert.strictEqual(plan.ready, true, texts(plan, 'blocker').join(' | '));
  assert.deepStrictEqual(names1(plan), ['Payroll:create']);
  assert.deepStrictEqual(plan.anchors.map(x => x.level + '=' + x.value + '@' + x.scope_id + '/' + x.source), ['Environment=Production@a1/query', 'Location=Dallas@a3/query']);
  assert(texts(plan, 'review').some(t => /outside the chosen parent/.test(t) && /HR \(Production\)/.test(t) && /Sandbox \(Development\)/.test(t) && /DNS \(Shared\)/.test(t)));
  assert.deepStrictEqual(plan.label_rows, [{ IP: '10.1.0.0/24', Environment: 'Production', Application: 'Payroll', Location: 'Dallas' }]);
  // one confirmed and one still proposed keeps the blocker
  assert(texts(B(d1, dallas, { rootId: 'a3', anchors: { Environment: { value: 'Production' } } }), 'blocker').some(t => /Confirm or clear/.test(t) && /Site or cloud = Dallas/.test(t) && !/Environment = Production/.test(t)));
  // a level set by the consultant where nothing was proposed is recorded against the parent
  plan = B(d1, acme, { rootId: 'a1', anchors: { Environment: { value: 'Production' }, Location: { value: 'Austin' } } });
  assert.deepStrictEqual(names1(plan), ['HR:create']);
  assert.deepStrictEqual(plan.anchors[1], { scope_id: 'a1', scope_name: 'Acme:Production', level: 'Location', value: 'Austin', source: 'consultant' });
  // Environment = Shared: the plan holds the shared services, directly under the parent
  const shared = acme.concat([{ id: 'a4', short_name: 'Shared', name: 'Acme:Shared', parent_app_scope_id: 'a0', short_query: eq('Environment', 'Shared') }]);
  plan = B(d1, shared, { rootId: 'a4', anchors: { Environment: { value: 'Shared' } } });
  assert.deepStrictEqual(names1(plan), ['DNS:create']); assert.strictEqual(plan.ready, true);
  assert.deepStrictEqual(plan.label_rows, [{ IP: '10.0.0.53', Environment: 'Shared', Application: 'DNS' }]);
  // Application anchored: nothing to build, said plainly, and no plan
  plan = B(d1, acme, { rootId: 'a2', anchors: { Environment: { value: 'Production' }, Application: { value: 'Payroll' } } });
  assert.strictEqual(plan.scopes.length, 0); assert.strictEqual(plan.ready, false); assert.strictEqual(plan.label_rows.length, 0);
  assert(texts(plan, 'blocker').some(t => /stands for the application "Payroll"\. There is nothing to build below an application scope/.test(t)));
  // unconfirmed anchors: the helper refuses the plan file (run the real helper, which reads the plan before any network call)
  const os = require('os'), cp = require('child_process');
  const tmp = fs.mkdtempSync(nodePath.join(os.tmpdir(), 'csw-'));
  const path3 = name => nodePath.join(tmp, name);
  const pendingPlan = nodePath.join(tmp, 'pending - CSW Scope Plan.json');
  fs.writeFileSync(pendingPlan, JSON.stringify(P.buildPlan(clone(d1), acme, { rootId: 'a1' }), null, 2));
  assert(!/"ui"/.test(fs.readFileSync(pendingPlan, 'utf8')), 'planner-only state is not saved in the plan file');
  const helper = nodePath.join(__dirname, '..', 'csw_scope_helper.py');
  const runHelper = file => cp.spawnSync(process.platform === 'win32' ? 'py' : 'python3', ['-B', helper, 'apply', '--plan', file, '--out-dir', tmp],
    { encoding: 'utf8', env: Object.assign({}, process.env, { CSW_URL: 'https://127.0.0.1:9', CSW_API_KEY: 'a'.repeat(32), CSW_API_SECRET: 'b'.repeat(40) }) });
  let res = runHelper(pendingPlan);
  assert.strictEqual(res.status, 1, res.stdout + res.stderr); assert(/This plan still has blockers/.test(res.stdout), res.stdout);
  // and the helper accepts the format of a confirmed plan (it gets as far as trying to reach the tenant)
  const okPlan = nodePath.join(tmp, 'ok - CSW Scope Plan.json');
  fs.writeFileSync(okPlan, JSON.stringify(P.buildPlan(clone(d1), acme, { rootId: 'a1', anchors: { Environment: { value: 'Production' } } }), null, 2));
  res = cp.spawnSync(process.platform === 'win32' ? 'py' : 'python3', ['-B', '-c',
    'import importlib.util,sys,json\nspec=importlib.util.spec_from_file_location("h",sys.argv[1]);H=importlib.util.module_from_spec(spec);spec.loader.exec_module(H)\np=H.load_plan(sys.argv[2])\nprint(p["schema_version"], H.plan_fingerprint(p["scopes"])==p["fingerprint"], len(p["anchors"]))', helper, okPlan], { encoding: 'utf8' });
  assert.strictEqual(res.stdout.trim(), '3 True 1', res.stdout + res.stderr);

  // 7.2 the planner and the helper agree: a difference only in capital letters is the same scope, and both spellings are named
  const caps = [acme[0], { id: 'c1', short_name: 'production', name: 'Acme:production', parent_app_scope_id: 'a0', short_query: { type: 'eq', field: 'user_environment', value: 'PRODUCTION' } }];
  plan = B(d1, caps, { rootId: 'a0' });
  assert.strictEqual(plan.scopes.find(s => s.short_name === 'Production').status, 'exists');
  assert(texts(plan, 'review').some(t => /same scope with different capital letters/.test(t) && /names it "production"/.test(t) && /names it "Production"/.test(t) && /user_environment = "PRODUCTION"/.test(t) && /user_Environment = "Production"/.test(t)), texts(plan, 'review').join(' | '));
  const other = [acme[0], { id: 'c1', short_name: 'Production', name: 'Acme:Production', parent_app_scope_id: 'a0', short_query: { type: 'eq', field: 'hostname', value: 'production' } }];
  assert.strictEqual(B(d1, other, { rootId: 'a0', anchors: { Environment: { value: '' } } }).scopes.find(s => s.short_name === 'Production').status, 'conflict');

  // D18: child scopes are counted per top-level scope
  const twoTops = acme.concat([{ id: 'b0', short_name: 'Second', name: 'Second', parent_app_scope_id: null, short_query: {} }]
    .concat(Array.from({ length: 5 }, (_, i) => ({ id: 'b' + (i + 1), short_name: 'k' + i, name: 'Second:k' + i, parent_app_scope_id: 'b0', short_query: {} }))));
  plan = B(d1, twoTops, { rootId: 'a0' });
  assert.strictEqual(plan.source.existing_scope_count, 2, 'only scopes with a parent, under the same top-level scope');
  assert.strictEqual(plan.checks[0].value, 2 + plan.scopes.filter(s => s.status === 'create').length);
  assert.strictEqual(B(d1, twoTops, { rootId: 'a0', tenantChildCount: 40 }).source.existing_scope_count, 40);
  assert.strictEqual(B(d1, twoTops, { rootId: 'a0', tenantChildCount: 0 }).source.existing_scope_count, 0);

  // section 6: files that are too new are refused in plain words, and older ones still load
  assert(/scope list file is too new for this planner: it uses export format 3 and this planner understands up to 2/.test(P.loadExisting({ schema: 'csw-scope-export', schema_version: 3, scopes: acme })));
  assert.strictEqual(P.loadExisting({ schema: 'csw-scope-export', schema_version: 1, scopes: acme }), '');
  assert.strictEqual(P.loadExisting({ schema: 'csw-scope-export', schema_version: 2, scopes: acme }), '');
  assert.strictEqual(P.loadExisting(acme), '');
  assert(/answers file is too new/.test(P.loadAnswers(Object.assign(clone(d1), { schema_version: 5 }))));
  for (const v of [1, 2, 3, 4]) { assert.strictEqual(P.loadAnswers(Object.assign(clone(d1), { schema_version: v })), ''); }

  // the planner page: What The Parent Scope Stands For
  const doc2 = w.document, box = doc2.getElementById('anchor-box'), sel0 = doc2.getElementById('root-sel');
  P.loadExisting({ schema: 'csw-scope-export', schema_version: 1, tenant_child_scope_count: 2, scopes: dallas }); P.loadAnswers(clone(d1)); P.rebuild();
  assert.strictEqual(box.hidden, false);
  assert.strictEqual(doc2.querySelectorAll('#anchor-rows .anchor-row').length, 4);
  assert.strictEqual(doc2.getElementById('anchor-Environment-confirm'), null, 'the top-level scope proposes nothing');
  sel0.value = 'a3'; sel0.dispatchEvent(new w.Event('change'));
  assert.strictEqual(P.getPlan().ready, false);
  assert.strictEqual(doc2.getElementById('anchor-Environment').value, 'Production');
  assert(/Proposed from the query of "Acme:Production"/.test(doc2.getElementById('anchor-rows').textContent));
  assert.strictEqual(doc2.getElementById('b-labels').disabled, true);
  doc2.getElementById('anchor-Environment-confirm').click();
  assert.strictEqual(P.getPlan().anchors.length, 1); assert.strictEqual(P.getPlan().ready, false, 'Location is still only proposed');
  doc2.getElementById('anchor-Location-confirm').click();
  assert.strictEqual(P.getPlan().ready, true); assert.strictEqual(P.getPlan().anchors.length, 2);
  assert.strictEqual(doc2.getElementById('verdict').textContent, 'Ready To Build');
  assert(/What the parent scope stands for: Environment = Production \(from the query of "Acme:Production"\); Site or cloud = Dallas/.test(doc2.getElementById('anchor-line').textContent));
  assert(/Confirmed/.test(doc2.getElementById('anchor-rows').textContent));
  const locSel = doc2.getElementById('anchor-Location'); locSel.value = ''; locSel.dispatchEvent(new w.Event('change'));
  assert.strictEqual(P.getPlan().anchors.length, 1); assert(/Cleared\. The proposal was Dallas\./.test(doc2.getElementById('anchor-rows').textContent));
  const locSel2 = doc2.getElementById('anchor-Location'); locSel2.value = 'Austin'; locSel2.dispatchEvent(new w.Event('change'));
  assert.deepStrictEqual(Array.from(P.getPlan().anchors, x => x.value + '/' + x.source), ['Production/query', 'Austin/consultant']);
  // choosing a different parent drops the earlier choices
  sel0.value = 'a1'; sel0.dispatchEvent(new w.Event('change'));
  assert.strictEqual(P.getPlan().anchors.length, 0); assert.strictEqual(doc2.getElementById('anchor-Environment-confirm') !== null, true);
  // no scope list: the section is hidden
  P.loadAnswers(clone(fixed)); doc2.getElementById('f-existing').dispatchEvent(new w.Event('change'));
  assert.strictEqual(box.hidden, true);
  assert(/CSW Scope Builder version 1\.2/.test(doc2.body.textContent));

  // ---------- Phase 2 (release 1.2): the change plan ----------
  {
  // 8.4: one query rule, shared with the helper through tests/rules.json
  RULES.equivalence.forEach(c => {
    assert.deepStrictEqual(Array.from(P.sameQuery(c.a, c.b)), [c.same, c.exact], JSON.stringify(c));
    assert.deepStrictEqual(Array.from(P.sameQuery(c.b, c.a)), [c.same, c.exact], JSON.stringify(c));
  });
  RULES.describe.forEach(c => assert.strictEqual(P.describeQuery(c.q), c.text, JSON.stringify(c)));
  assert.strictEqual(P.planFingerprint(RULES.fingerprint_v3.scopes), RULES.fingerprint_v3.sha256);
  const flipped = clone(RULES.fingerprint_v3.scopes); flipped[3].approved = true;
  assert.strictEqual(P.planFingerprint(flipped), RULES.fingerprint_v3.sha256_when_the_removal_is_approved, 'approving a change makes it a different plan');

  // the tenant: Acme > Production (Environment) > [Payroll, "Human Resources" (query is HR's), Legacy > LegacyKid], Development > [HR]
  const subnet = v => ({ type: 'subnet', field: 'ip', value: v });
  const dep = (w, f, r) => ({ workspaces: w, inventory_filters: f, roles: r });
  const t2 = [
    { id: 'a0', short_name: 'Acme', name: 'Acme', parent_app_scope_id: null, short_query: subnet('0.0.0.0/0'), dependents: dep([], [], []) },
    { id: 'a1', short_name: 'Production', name: 'Acme:Production', parent_app_scope_id: 'a0', short_query: eq('Environment', 'Production'), dependents: dep([], [], []) },
    { id: 'a2', short_name: 'payroll', name: 'Acme:Production:payroll', parent_app_scope_id: 'a1', short_query: subnet('10.1.0.0/24'), dependents: dep([{ id: 'w1', name: 'Payroll policy' }], [], []) },
    { id: 'a3', short_name: 'Human Resources', name: 'Acme:Production:Human Resources', parent_app_scope_id: 'a1', short_query: JSON.stringify({ type: 'and', filters: [eq('application', 'hr')] }), dependents: dep([], [], []) },
    { id: 'a4', short_name: 'Legacy', name: 'Acme:Production:Legacy', parent_app_scope_id: 'a1', short_query: subnet('10.9.0.0/16'), dependents: dep([], [], []) },
    { id: 'a5', short_name: 'LegacyKid', name: 'Acme:Production:Legacy:LegacyKid', parent_app_scope_id: 'a4', short_query: subnet('10.9.1.0/24'), dependents: dep([], [], []) },
    { id: 'a6', short_name: 'Development', name: 'Acme:Development', parent_app_scope_id: 'a0', short_query: eq('Environment', 'Development'), dependents: dep([], [], []) },
    { id: 'a7', short_name: 'Sandbox', name: 'Acme:Production:Sandbox', parent_app_scope_id: 'a1', short_query: subnet('10.2.0.0/24'), dependents: dep([], [{ id: 'f1', name: 'Sandbox hosts' }], []) },
    { id: 'a8', short_name: 'Old Billing', name: 'Acme:Production:Old Billing', parent_app_scope_id: 'a1', short_query: subnet('10.3.0.0/24'), dependents: dep([], [], 'not read') }];
  const depsRead = { workspaces: { read: true }, inventory_filters: { read: true }, roles: { read: false, reason: 'x', needs: 'y' } };
  const B2 = (changes, more) => B(d1, t2, Object.assign({ rootId: 'a0', dependents: depsRead, changes: changes || {} }, more || {}));
  const item = (pl, name) => pl.scopes.find(s => s.short_name === name || (s.before && s.before.short_name === name));
  plan = B2();
  assert.strictEqual(plan.schema_version, 3); assert.strictEqual(plan.ready, true, texts(plan, 'blocker').join(' | '));
  // 8.2: every scope carries one action
  assert.deepStrictEqual(plan.scopes.map(s => (s.before ? s.before.short_name : s.short_name) + '>' + s.action),
    ['Production>keep', 'Development>keep', 'Shared>create', 'payroll>requery', 'Human Resources>rename', 'Sandbox>create', 'DNS>create',
     'Legacy>leave', 'LegacyKid>leave', 'Old Billing>leave', 'Sandbox>leave']);
  assert(plan.scopes.every(s => ['keep', 'create', 'rename', 'requery', 'rename_requery', 'remove', 'leave', 'by_hand'].includes(s.action)));
  // 8.3 rule 2: same parent and same name with a different query is a proposed query change, not approved
  let it = item(plan, 'payroll');
  assert.strictEqual(it.match_rule, 'same parent and same name'); assert.strictEqual(it.approved, false); assert.strictEqual(it.status, 'conflict');
  assert.deepStrictEqual(it.before, { id: 'a2', short_name: 'payroll', short_query: subnet('10.1.0.0/24'), parent_id: 'a1' });
  assert.deepStrictEqual(it.after, { short_name: 'payroll', short_query: eq('Application', 'Payroll') });
  assert.deepStrictEqual(it.short_query, eq('Application', 'Payroll'));
  assert(texts(plan, 'review').some(t => /"Payroll" under "Production" already exists with a different query: address is in 10\.1\.0\.0\/24\. A change to "Application is Payroll" is proposed/.test(t) && /Nothing is changed unless you approve it/.test(t)));
  // 8.3 rule 3: same parent and an equivalent query under another name is a proposed rename, not approved
  it = item(plan, 'Human Resources');
  assert.strictEqual(it.action, 'rename'); assert.strictEqual(it.match_rule, 'same parent and equivalent query'); assert.strictEqual(it.approved, false);
  assert.strictEqual(it.before.short_name, 'Human Resources'); assert.strictEqual(it.after.short_name, 'HR'); assert.strictEqual(it.short_name, 'HR');
  assert.deepStrictEqual(it.after.short_query, { type: 'and', filters: [eq('application', 'hr')] }, 'a rename keeps the query the tenant has');
  assert(texts(plan, 'review').some(t => /"HR" under "Production" already exists under the name "Human Resources" with the same query\. A rename is proposed/.test(t)));
  // 8.3 rule 4: the same name elsewhere is not a match, only a question
  it = plan.scopes.find(s => s.short_name === 'Sandbox' && s.action === 'create');
  assert.strictEqual(plan.scopes.find(s => s.ref === it.parent_ref).short_name, 'Development'); assert.deepStrictEqual(it.may_exist, ['a7']);
  assert(texts(plan, 'review').some(t => /"Sandbox", planned under "Development", may already exist as "Acme:Production:Sandbox"\. It is not treated as the same scope/.test(t) && /cannot move a scope/.test(t)));
  // before and after: create has only after, leave and keep carry before
  assert.strictEqual(it.before, undefined); assert.deepStrictEqual(it.after, { short_name: 'Sandbox', short_query: eq('Application', 'Sandbox') });
  assert.deepStrictEqual(item(plan, 'Legacy').before, { id: 'a4', short_name: 'Legacy', short_query: subnet('10.9.0.0/16'), parent_id: 'a1' });
  assert.strictEqual(item(plan, 'LegacyKid').parent_ref, item(plan, 'Legacy').ref); assert.strictEqual(item(plan, 'Legacy').parent_ref, item(plan, 'Production').ref);
  // 8.2 rule 2: the planner never proposes a removal by itself, and 8.2 rule 4: the parent and anything above it is never an item
  assert(!plan.scopes.some(s => s.action === 'remove' || s.action === 'by_hand'));
  assert(!plan.scopes.some(s => s.before && s.before.id === 'a0'));
  // 8.6: the warnings, the counts, and a verdict tied to blockers only
  assert(texts(plan, 'review').some(t => t === 'Renaming a scope changes the full name of that scope and every scope below it. Anything that refers to them by full name is affected.'));
  assert(texts(plan, 'review').some(t => /^Changing a scope's query changes which workloads are in it and in every scope below it\. Policies in workspaces on those scopes will apply to a different set of workloads\. The change takes effect when it is committed\.$/.test(t)));
  assert(!texts(plan, 'review').some(t => /cannot be reversed with its original ID/.test(t)));
  assert.deepStrictEqual(plan.actions, { counts: { keep: 2, create: 3, rename: 1, requery: 1, rename_requery: 0, remove: 0, leave: 4, by_hand: 0 }, need_approval: 2, approved: 0 });
  assert(plan.todo.some(t => /^2 proposed changes to existing scopes in this plan are not approved\. The apply command skips them/.test(t)));
  assert.strictEqual(plan.checks[0].value, plan.source.existing_scope_count + 3, 'only creates count toward the limit');
  // approving: by scope, and it changes the fingerprint
  let plan2 = B2({ approved: { a2: true, a3: true, a4: true } });
  assert.strictEqual(item(plan2, 'payroll').approved, true); assert.strictEqual(item(plan2, 'Human Resources').approved, true);
  assert.strictEqual(item(plan2, 'Legacy').action, 'leave'); assert.strictEqual(item(plan2, 'Legacy').approved, false, 'an approval alone never removes anything');
  assert.notStrictEqual(plan2.fingerprint, plan.fingerprint); assert.strictEqual(plan2.actions.approved, 2); assert.strictEqual(plan2.ready, true);
  assert(plan2.todo.some(t => /2 approved changes to existing scopes/.test(t) && /--allow-changes \(renames and query changes\) after --write/.test(t) && !/--allow-removals/.test(t)));
  // removal: the consultant marks it, it still needs its own approval, and the third warning appears
  plan2 = B2({ remove: { a4: true, a5: true } });
  assert.strictEqual(item(plan2, 'Legacy').action, 'remove'); assert.strictEqual(item(plan2, 'LegacyKid').action, 'remove');
  assert.strictEqual(item(plan2, 'Legacy').approved, false); assert.strictEqual(item(plan2, 'Legacy').after, undefined, 'a removal has only a before');
  assert(texts(plan2, 'review').some(t => t === 'Removing a scope cannot be reversed with its original ID. Undo recreates it with a new ID.'));
  plan2 = B2({ remove: { a4: true, a5: true }, approved: { a4: true, a5: true } });
  assert.strictEqual(item(plan2, 'Legacy').approved, true); assert.strictEqual(plan2.actions.counts.remove, 2);
  assert(plan2.todo.some(t => /--allow-removals \(removals\) after --write/.test(t) && !/--allow-changes/.test(t)));
  // 8.8: removing a parent while keeping its child is refused: it becomes "by hand" with the reason
  plan2 = B2({ remove: { a4: true }, approved: { a4: true } });
  it = item(plan2, 'Legacy');
  assert.strictEqual(it.action, 'by_hand'); assert.strictEqual(it.approved, false);
  assert(/It has scopes under it that are not also being removed: LegacyKid/.test(it.reason));
  assert(texts(plan2, 'review').some(t => /"Acme:Production:Legacy" is marked for removal, but this tool will not remove it\. It has scopes under it/.test(t)));
  assert.strictEqual(plan2.actions.counts.remove, 0); assert.strictEqual(plan2.ready, true);
  // 8.2 rule 3: an old scope with something attached becomes "by hand", and its parent with it
  plan2 = B2({ remove: { a7: true }, approved: { a7: true } });
  it = plan2.scopes.find(s => s.before && s.before.id === 'a7');
  assert.strictEqual(it.action, 'by_hand'); assert(/It is in use: 1 inventory filter \(Sandbox hosts\)\. Clear what depends on it in Secure Workload first\./.test(it.reason), it.reason);
  // 8.5.3: a kind that was not read means "possibly in use", said plainly, and the removal is still allowed
  plan2 = B2({ remove: { a8: true }, approved: { a8: true } });
  it = item(plan2, 'Old Billing');
  assert.strictEqual(it.action, 'remove'); assert.strictEqual(it.approved, true); assert.strictEqual(it.dependents.roles, 'not read');
  assert(texts(plan2, 'review').some(t => /does not say whether roles depend on the scopes marked for removal, so each is treated as possibly in use\. The tenant refuses the removal if anything depends/.test(t)), texts(plan2, 'review').join(' | '));
  // a scope list from helper 1.1 has no dependents at all: everything is "not read"
  const bare = t2.map(x => { const y = clone(x); delete y.dependents; return y; });
  plan2 = B(d1, bare, { rootId: 'a0', changes: { remove: { a7: true } } });
  it = plan2.scopes.find(s => s.before && s.before.id === 'a7');
  assert.strictEqual(it.action, 'remove'); assert.deepStrictEqual(it.dependents, { workspaces: 'not read', inventory_filters: 'not read', roles: 'not read' });
  assert(texts(plan2, 'review').some(t => /workspaces, inventory filters, roles depend on the scopes marked for removal, because it was saved by an older helper/.test(t)));
  // a matched scope can never be marked for removal, and neither can the parent
  plan2 = B2({ remove: { a1: true, a2: true, a0: true }, approved: { a1: true, a0: true } });
  assert.strictEqual(item(plan2, 'Production').action, 'keep'); assert.strictEqual(item(plan2, 'payroll').action, 'requery'); assert(!plan2.scopes.some(s => s.action === 'remove'));
  // with no scope list nothing existing is touched, and with an anchored parent the same rules apply below it
  plan2 = B(d1, null);
  assert(plan2.scopes.every(s => s.action === 'create' && s.approved === false && !s.before)); assert.strictEqual(plan2.actions.need_approval, 0);
  plan2 = B(d1, t2, { rootId: 'a1', dependents: depsRead, anchors: { Environment: { value: 'Production' } } });
  assert.deepStrictEqual(plan2.scopes.map(s => (s.before ? s.before.short_name : s.short_name) + '>' + s.action),
    ['payroll>requery', 'Human Resources>rename', 'Legacy>leave', 'LegacyKid>leave', 'Old Billing>leave', 'Sandbox>leave']);

  // the helper accepts the planner's format 3 file and reads the same work out of it (no network: the check is read-only)
  const fullPlan = B2({ approved: { a2: true, a3: true, a4: true, a5: true }, remove: { a4: true, a5: true } });
  const fullFile = path3('full - CSW Scope Plan.json'); fs.writeFileSync(fullFile, JSON.stringify(fullPlan, null, 2));
  const liveFile = path3('live.json'); fs.writeFileSync(liveFile, JSON.stringify(t2.map(x => Object.assign(clone(x), { short_query: typeof x.short_query === 'string' ? JSON.parse(x.short_query) : x.short_query }))));
  const py = (file, live) => cp.spawnSync(process.platform === 'win32' ? 'py' : 'python3', ['-B', '-c', [
    'import importlib.util,sys,json',
    'spec=importlib.util.spec_from_file_location("h",sys.argv[1]);H=importlib.util.module_from_spec(spec);spec.loader.exec_module(H)',
    'p=H.load_plan(sys.argv[2]);live=json.load(open(sys.argv[3]));parent=[s for s in live if s["id"]=="a0"][0]',
    'try:',
    '    w=H.check_changes_plan(p,live,parent)',
    '    print(json.dumps({"fp":H.plan_fingerprint(p["scopes"])==p["fingerprint"],"create":[a["short_name"] for a in w["create"]],"rename":[e["live"]["id"] for e in w["rename"]],"requery":[e["live"]["id"] for e in w["requery"]],"remove":[e["live"]["id"] for e in w["remove"]],"skipped":len(w["skipped"]),"by_hand":len(w["by_hand"]),"keep":w["keep"],"leave":w["leave"]}))',
    'except H.HelperError as e:',
    '    print(json.dumps({"error":str(e)}))'].join('\n'), helper, file, live], { encoding: 'utf8' });
  res = py(fullFile, liveFile);
  assert.deepStrictEqual(JSON.parse(res.stdout), { fp: true, create: ['Shared', 'Sandbox', 'DNS'], rename: ['a3'], requery: ['a2'], remove: ['a5', 'a4'], skipped: 0, by_hand: 0, keep: 2, leave: 2 }, res.stdout + res.stderr);
  const noneFile = path3('none - CSW Scope Plan.json'); fs.writeFileSync(noneFile, JSON.stringify(B2({ remove: { a4: true, a5: true } }), null, 2));
  assert.deepStrictEqual(JSON.parse(py(noneFile, liveFile).stdout), { fp: true, create: ['Shared', 'Sandbox', 'DNS'], rename: [], requery: [], remove: [], skipped: 4, by_hand: 0, keep: 2, leave: 2 });
  // and it stops when the tenant no longer looks like the plan's "before"
  const moved = JSON.parse(fs.readFileSync(liveFile, 'utf8')); moved.find(x => x.id === 'a3').short_name = 'People';
  const movedFile = path3('moved.json'); fs.writeFileSync(movedFile, JSON.stringify(moved));
  assert(/changed since the plan was made: "Human Resources" is now named "People"/.test(JSON.parse(py(fullFile, movedFile).stdout).error));

  // 8.6.1: the page section, with a tick box per item, grouped
  P.loadExisting({ schema: 'csw-scope-export', schema_version: 2, tenant_child_scope_count: 8, dependents: depsRead, scopes: t2 }); P.loadAnswers(clone(d1)); P.rebuild();
  const repBox = doc2.getElementById('report'), heads2 = () => Array.from(repBox.querySelectorAll('h2'), x => x.textContent);
  assert.deepStrictEqual(heads2().slice(3, 5), ['4. Changes To Existing Scopes', '5. Scopes In Build Order'], 'the changes sit above the build order');
  const groups = () => Array.from(repBox.querySelectorAll('[data-group]'), x => x.getAttribute('data-group') + ':' + x.querySelectorAll('tbody tr').length);
  assert.deepStrictEqual(groups(), ['Rename:1', 'Change Query:1', 'Not In This Plan (Left Alone):4']);
  let rowText = g => repBox.querySelector('[data-group="' + g + '"] tbody tr').textContent;
  assert(/Acme:Production:Human Resources"Human Resources": application is hr"HR": application is hrNothing found$/.test(rowText('Rename')), rowText('Rename'));
  assert(/Acme:Production:payroll"payroll": address is in 10\.1\.0\.0\/24"payroll": Application is Payroll1 workspace \(Payroll policy\)/.test(rowText('Change Query')), rowText('Change Query'));
  assert.strictEqual(doc2.getElementById('approve-a2').checked, false); assert.strictEqual(doc2.getElementById('approve-a2').disabled, false);
  assert.strictEqual(doc2.getElementById('approve-a4'), null, 'a scope that is left alone has no approval box, only a removal box');
  assert(/Actions: 3 create, 2 keep, 1 rename, 1 change query, 4 leave alone\. 0 of 2 proposed changes to existing scopes are approved\. A change that is not approved is not made\./.test(doc2.getElementById('action-line').textContent), doc2.getElementById('action-line').textContent);
  // 8.6.4: unapproved items do not block
  assert.strictEqual(doc2.getElementById('verdict').textContent, 'Ready To Build');
  const tickBox = (id, on) => { const b = doc2.getElementById(id); b.checked = on; b.dispatchEvent(new w.Event('change')); };
  tickBox('approve-a2', true);
  assert.strictEqual(item(P.getPlan(), 'payroll').approved, true); assert.strictEqual(doc2.getElementById('approve-a2').checked, true);
  assert(/1 of 2 proposed changes/.test(doc2.getElementById('action-line').textContent));
  tickBox('remove-a5', true); tickBox('remove-a4', true);
  assert.deepStrictEqual(groups(), ['Rename:1', 'Change Query:1', 'Remove:2', 'Not In This Plan (Left Alone):2']);
  assert.strictEqual(doc2.getElementById('approve-a4').checked, false, 'marking for removal does not approve it');
  tickBox('approve-a4', true); tickBox('approve-a5', true);
  assert.strictEqual(P.getPlan().actions.approved, 3); assert.strictEqual(item(P.getPlan(), 'Legacy').approved, true);
  // unmarking the child turns the parent into "by hand" and drops the child's approval
  tickBox('remove-a5', false);
  assert.deepStrictEqual(groups(), ['Rename:1', 'Change Query:1', 'By Hand:1', 'Not In This Plan (Left Alone):3']);
  assert(/Not changed by this tool\. It has scopes under it that are not also being removed: LegacyKid/.test(rowText('By Hand')));
  tickBox('remove-a5', true);
  assert.strictEqual(item(P.getPlan(), 'LegacyKid').approved, false, 'approval has to be given again');
  // the tree shows what is outside the plan and what is to be removed
  assert(/LegacyTo remove/.test(repBox.querySelector('ul.tree').textContent) && /Old BillingNot in this plan/.test(repBox.querySelector('ul.tree').textContent));
  // the build order table holds only the planned scopes, with the query in plain words
  const orderRows = Array.from(repBox.querySelectorAll('h2')).find(x => x.textContent === '5. Scopes In Build Order').nextElementSibling.nextElementSibling.querySelectorAll('tbody tr');
  assert.strictEqual(orderRows.length, 7); assert(/1ProductionAcmeEnvironment is ProductionAlready exists/.test(orderRows[0].textContent), orderRows[0].textContent);
  assert(Array.from(orderRows).some(r => /HRProductionapplication is hrExists under another name/.test(r.textContent)));
  // choosing a different parent, or loading a different scope list, drops every tick
  sel0.value = 'a1'; sel0.dispatchEvent(new w.Event('change'));
  assert.strictEqual(P.getPlan().actions.approved, 0); assert(!P.getPlan().scopes.some(s => s.action === 'remove'));
  // the downloaded plan file carries what the helper needs
  P.loadExisting({ schema: 'csw-scope-export', schema_version: 2, dependents: depsRead, scopes: t2 }); P.rebuild();
  const saved = JSON.parse(JSON.stringify(P.getPlan()));
  assert.strictEqual(saved.schema_version, 3); assert.strictEqual(saved.tool_version, '1.2'); assert(saved.scopes.every(s => 'action' in s && 'approved' in s));
  // with no scope list the section says so
  P.loadAnswers(clone(fixed)); doc2.getElementById('f-existing').dispatchEvent(new w.Event('change'));
  assert.strictEqual(doc2.getElementById('changes-none').textContent, 'No scope list was loaded, so no existing scope is touched.');
  // a printed or re-rendered plan with no handler shows the boxes but cannot change them
  const still = doc2.createElement('div'); P.renderReport(B2({ approved: { a2: true } }), still);
  assert.strictEqual(still.querySelector('#approve-a2').disabled, true); assert.strictEqual(still.querySelector('#approve-a2').checked, true);

  }

  // 10. page flow: load answers, render, buttons
  assert.strictEqual(P.loadAnswers({ schema: 'nope' }) !== '', true);
  assert.strictEqual(P.loadAnswers(clone(fixed)), '');
  assert.strictEqual(P.loadExisting({ foo: 1 }) !== '', true);
  assert.strictEqual(P.loadExisting(existing), '');
  P.rebuild();
  const d = w.document;
  assert.strictEqual(d.getElementById('report').hidden, false);
  assert.strictEqual(d.getElementById('verdict').textContent, 'Ready To Build');
  assert.strictEqual(d.querySelectorAll('#report h2').length, 9);
  assert.strictEqual(d.querySelectorAll('#report ul.tree li').length, 14, 'root, 12 planned scopes, and 1 existing scope that is left alone');
  assert.strictEqual(d.getElementById('b-plan').disabled, false);
  assert.strictEqual(d.getElementById('b-labels').disabled, false);
  P.loadAnswers(clone(sample)); P.rebuild();
  assert.strictEqual(P.getPlan().ready, false);
  assert.strictEqual(d.getElementById('b-labels').disabled, true, 'no label file while blockers exist');
  assert.strictEqual(d.getElementById('b-plan').disabled, false);
  assert(/cannot be downloaded until the blockers are fixed/.test(d.getElementById('report').textContent));
  P.loadAnswers(clone(fixed)); P.rebuild();
  assert(/^\d{4}-\d{2}-\d{2} acme - CSW Scope Plan$/.test(d.title), d.title);
  const out = JSON.parse(JSON.stringify(P.getPlan()));
  assert.strictEqual(out.schema, 'csw-scope-plan');
  assert.strictEqual(out.schema_version, 3);
  assert.strictEqual(out.tool_version, '1.2'); assert.strictEqual(out.planner_version, undefined);
  assert(/^[0-9a-f]{64}$/.test(out.fingerprint)); assert.deepStrictEqual(out.anchors, []);

  console.log('ALL PASS');
})().catch(e => { console.error(e.message, (e.stack || '').split('\n')[1]); process.exit(1); });
