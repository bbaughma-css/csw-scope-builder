# CSW Scope Builder

Version 1.2 | 19 Nov 2026 | Supersedes: 1.1

CSW Scope Builder turns a customer's answers about their environment into a Cisco Secure Workload (CSW) scope tree that follows Cisco's scope design principles. It produces a plan document, a label file, and a plan file. It can create the scopes in the customer's tenant under a parent scope the customer chooses. From version 1.2 it can also rename an existing scope, change its query, or remove it, but only for changes the consultant approves in the plan and the customer allows when building.

A scope is a named group of workloads defined by a query. The scope tree is how those groups are arranged, and it is the anchor for policy and for access control.

## Quick Start: Running The Helper

This is the short version for the person who runs `csw_scope_helper.py` against the tenant. Every command only previews unless it ends in `--write`. The rest of this README has the detail.

### Before You Start

| You need | How to check or get it |
|---|---|
| Python 3.8 or later | Run `python3 --version`. On Windows run `py --version` |
| The helper file | Save `csw_scope_helper.py` in a folder of its own. Nothing else has to be installed |
| Your tenant address | For example `https://example.tetrationcloud.com` |
| A Secure Workload API key and secret | A pair of short values: the key is 32 characters and the secret is 40. The key needs the capability `user_role_scope_management`. Create it with Cisco's current directions. The long Security Cloud Control token that starts with `eyJ` does not work |
| The full name of the scope to build under | For example `Acme:Production`. Copy it from Organize > Scopes and Inventory |
| The files from your Cisco contact | The plan file (ends in `CSW Scope Plan.json`) and the label file (ends in `CSW Labels.csv`). Save both in the same folder as the helper. You get these after step 1 |

Open a terminal in that folder:

```
cd "path to the folder"
```

Each command asks for the tenant address, the key, and the secret. They are never saved. On Windows, type `py` in place of `python3` in every command below. Replace the file names and the scope name with your own.

### Step 1: Save Your Scope List (Only If The Tenant Already Has Scopes)

```
python3 csw_scope_helper.py export --under "Acme:Production"
```

It saves a file that ends in `CSW Existing Scopes.json`. Send that file to your Cisco contact. They send back the plan document, the label file, and the plan file. Leave out `--under` and the scope name to save the whole tenant.

### Step 2: Check The Label File, Then Upload It

```
python3 csw_scope_helper.py check-labels --labels "2026-11-19 Acme - CSW Labels.csv"
```

It changes nothing and lists every value an upload would replace. Then upload the file yourself in Secure Workload under Organize > Label Management > User Defined Label Upload, with the Merge operation. The helper does not upload labels.

### Step 3: Preview The Plan

```
python3 csw_scope_helper.py apply --plan "2026-11-19 Acme - CSW Scope Plan.json" --under "Acme:Production"
```

It lists everything the plan would do and changes nothing. Read the list.

### Step 4: Build

The same command with `--write` on the end:

```
python3 csw_scope_helper.py apply --plan "2026-11-19 Acme - CSW Scope Plan.json" --under "Acme:Production" --write
```

Type yes when asked. It creates each scope, reads it back, and saves a record file that ends in `CSW Apply Record.json`. Keep that file.

### Step 5: Only If The Plan Changes Existing Scopes

The plan document lists these under "Changes To Existing Scopes". Step 4 never touches them. To make the approved renames, query changes, and removals:

```
python3 csw_scope_helper.py apply --plan "2026-11-19 Acme - CSW Scope Plan.json" --under "Acme:Production" --write --allow-changes --allow-removals
```

It lists each change, before and after, and waits for you to type yes. Leave off `--allow-removals` to rename and change queries only. Add `--no-commit` to make the changes and commit them yourself in Secure Workload after you have looked at them.

### If You Need To Reverse A Build

Preview the reversal, then run it:

```
python3 csw_scope_helper.py undo --record "2026-11-19 081200 Production - CSW Apply Record.json"
python3 csw_scope_helper.py undo --record "2026-11-19 081200 Production - CSW Apply Record.json" --write
```

### If Something Stops Partway

Run the same command again. It reads the tenant first and does only what is missing.

## What Is In This Repository

| File | Who uses it | What it is |
|---|---|---|
| `index.html` | Consultant | Start page with the workflow and links to everything else |
| `interview.html` | Customer | Questionnaire. Works offline and sends nothing anywhere. Saves an answers file |
| `planner.html` | Consultant | Reads the answers file and builds the plan. Runs entirely in the browser |
| `csw_scope_helper.py` | Customer | Python program that reads the tenant's scopes, checks labels, creates scopes, makes approved changes to existing scopes, and undoes a run |
| `customer-guide.html` | Customer | One page of instructions to send with the questionnaire and the helper |
| `tests/` | Maintainer | Automated tests for all three pieces and the shared rule tables (`rules.json`) |

Every piece carries the same version number, 1.2. Each page shows it, the helper prints it with `--version`, and every saved file records it as `tool_version`.

| File type | Format (`schema_version`) written by 1.2 | Older formats still read |
|---|---|---|
| Answers file | 4 | 1, 2, 3 |
| Scope list file | 2 | 1 |
| Plan file | 3 | 1, 2 |
| Record file | 3 | 1, 2 |

A plan file in format 1 or 2 still builds exactly as it did: it only creates scopes.

A page or the helper refuses a file in a newer format than it understands and says which file is too new.

## How It Works

1. The consultant emails the customer `interview.html`, `csw_scope_helper.py`, and `customer-guide.html`.
2. The customer fills out the questionnaire and sends back the answers file.
3. If the tenant already has scopes, the customer runs the helper's `export` command and sends back the scope list file.
4. The consultant opens `planner.html`, loads the files, and gets the plan. The consultant sends the customer the plan document (PDF), the label file, and the plan file.
5. The customer checks and uploads the label file, then creates the scopes with the helper's `apply` command or by hand.

The consultant never needs a login or an API key for the customer's tenant. The customer reads from the tenant in step 3 and writes to it in step 5.

## What The Consultant Does

1. Send the three customer files.
2. When the answers file arrives, open `planner.html` in a browser.
3. Under "Customer answers file", choose the answers file.
4. If the customer sent a scope list, choose it under "Existing scope list". Check "Build under this scope". It follows the customer's answer when they gave one.
5. Under "What The Parent Scope Stands For", confirm or clear each proposal. See "Building Under Any Scope" below.
6. Read the plan. Fix blockers with the customer before going further.
7. Under "Changes To Existing Scopes", tick the box beside each proposed change you approve. See "Changing Existing Scopes" below.
8. Use "Print Or Save As PDF", "Download Label File", and "Download Plan File", and send all three to the customer.

Files chosen in the planner are read by the browser only. Nothing is uploaded.

## Reading The Plan

The plan has nine sections: summary, findings, scope tree, changes to existing scopes, scopes in build order, label plan, limit checks, customer to-do list, and design rules with references. Every query is also written as one plain line, for example "Environment is Production and address is in 10.0.0.0/8".

| Finding type | Meaning |
|---|---|
| Blocker | Stops the build. The label file cannot be downloaded and the helper refuses the plan file |
| Review | Needs a decision from the consultant or the customer |
| Later Round | Information is missing. It does not stop this round |

## Building Under Any Scope

The parent can be any existing scope, not only the top one. An existing scope often already stands for a level of the tree. For example, a scope named Production with the query Environment = Production already is the Production environment. This tool calls that an anchor.

1. When a parent is chosen, the planner looks at the parent and every scope above it. It proposes an anchor when the scope's query is one "label equals value" on one of the plan's label names with a value the customer's answers contain, or when the scope's short name matches exactly one known value in exactly one level.
2. The planner never applies a proposal by itself. Each level has a row with a drop-down. Confirm the proposal, pick a different value, or choose "Not set". Until every proposal is confirmed or cleared, the plan carries a blocker.
3. A level that is set is not built again below the parent. Only the applications and shared services that belong to it are planned. The rest are listed in one Review finding and are not errors.
4. If the parent stands for Environment = Shared, the plan holds the shared services.
5. If the parent stands for an application, there is nothing to build below it and the plan is empty.
6. With nothing set, the plan is built as in version 1.0.

The label file still carries every label for the rows in the plan, including the levels that were set, because the workloads still need those labels.

## Changing Existing Scopes

Version 1.2 gives every scope in the plan one action.

| Action | Meaning | Changes the tenant |
|---|---|---|
| Keep | Exists and matches the plan | No |
| Create | New scope | Yes |
| Rename | Exists under another name with the same query | Yes |
| Change Query | Exists under the same name with a different query | Yes, and needs a commit |
| Rename And Change Query | Both. The planner does not propose this yet. The helper carries it out if a plan file lists it | Yes, and needs a commit |
| Remove | Exists and the consultant marked it for removal | Yes |
| Leave Alone | Exists below the parent, is not part of the plan, and is not touched | No |
| By Hand | A change the tool will not make, with the reason | No |

The rules:

1. Nothing that touches an existing scope is approved by default. Each rename, query change, and removal has a tick box under "Changes To Existing Scopes". An item that is not ticked is skipped by the helper and listed as skipped. Unapproved items do not stop the build.
2. The planner never proposes a removal. The consultant marks a left-alone scope for removal, and then approves it with a second tick.
3. A scope cannot be moved to a different parent. The update call in the Secure Workload API takes only the short name, the description, and the query. When a planned scope looks like one that already exists under a different parent, the plan creates a new one and raises a Review finding. Leave the old one, or mark it for removal.
4. A top-level scope is never renamed, changed, or removed. Neither is the chosen parent or anything above it.
5. A scope is removed only when every scope under it is also being removed and nothing is known to depend on it. Otherwise it becomes By Hand with the reason.
6. Each item records what the scope looks like now (before) and what it will look like (after). The helper checks the before against the tenant and stops if it differs.

What the customer does: preview with `apply --plan FILE`, then run with `--write`. Renames and query changes also need `--allow-changes`. Removals also need `--allow-removals`. For those two kinds the helper lists every change, before and after, and waits for a typed yes. `--yes` does not skip that.

What to tell the customer before approving:

- Renaming a scope changes the full name of that scope and every scope below it. Anything that refers to them by full name is affected.
- Changing a scope's query changes which workloads are in it and in every scope below it. Policies in workspaces on those scopes will apply to a different set of workloads. The change takes effect when it is committed.
- Removing a scope cannot be reversed with its original ID. Undo recreates it with a new ID, and anything that pointed at the old ID must be attached again by hand.

### What Depends On A Scope

The helper's `export` command also reads what depends on each scope, so the plan can say a scope is in use before anyone tries to remove it. It saves only the ID and name of each. It reads no policy content.

| What | API call | Capability the key needs |
|---|---|---|
| Workspaces | `GET /openapi/v1/applications` | `app_policy_management` |
| Inventory filters | `GET /openapi/v1/filters/inventories` | `app_policy_management` or `sensor_management` |
| Roles | `GET /openapi/v1/roles` | `user_role_scope_management`, as a site admin or an owner of the top-level scope |

If the key cannot read one of them, the export still succeeds and records that kind as "not read". The plan then treats every scope as possibly in use for that kind and says so. Whatever the export shows, the tenant has the final word: it refuses to remove a scope that something depends on, and the helper prints what it says, marks the item "in use", and does not try again.

## How Scopes Are Matched And Compared

The planner and the helper use one rule to decide whether two queries mean the same thing. Both are tested against the same tables in `tests/rules.json`.

Matching a planned scope to the tenant, in this order:

1. Same parent and same short name, ignoring capital letters. If the query is also the same, the scope is kept. If the query differs, a query change is proposed.
2. Same parent and an equivalent query under a different name. A rename is proposed.
3. Same short name or an equivalent query anywhere else in the scope list. This is not a match. A Review finding says "may already exist as" with the full name, and the consultant decides.

Comparing two queries:

1. JSON text is read into a structure first.
2. The members of an "and" or an "or" are sorted, so their order does not matter. An "and" or "or" with one member is the same as that member.
3. In a "label equals value" condition on an uploaded label (a field that starts with `user_`), capital letters in the label name and the value are ignored. Secure Workload label keys and values are not case sensitive. Every other value is compared exactly.
4. A query of a type the tool does not know is kept exactly as it is, shown as raw text, and matches only an identical one.

The types the tool reads are the ones Cisco lists for filters: eq, ne, lt, lte, gt, gte, range, in, regex, contains, subnet, and the combining types and, or, not.

When a kept scope differs from the plan only in capital letters, a Review finding names both spellings and the tenant's spelling is kept.

## Building In Rounds

Missing information does not stop the process. The customer sends what they know, and the plan builds what it can. Later, the customer opens the questionnaire, chooses "Continue From A Saved File", adds what they have learned, answers Yes to existing scopes, runs `export` again, and sends both files. The next plan only adds to what exists.

Use the same label names in every round for the same customer. With different names the planner sees the earlier scopes as existing with a different query and leaves them alone.

## Label Names

The plan labels each workload with four labels. The default names are Environment, Application, Location, and Zone. The planner page lets the consultant change any of them.

Change a name when the tenant already uses it for something else. The export file carries the tenant's existing label names, and the plan flags any name already in use. Keep a name only if it already means the same thing in that tenant.

Scope queries use labels uploaded to Secure Workload. The Secure Workload API names an uploaded label with the prefix `user_`, for example `user_Environment`.

## Uploading Labels

Label upload is a manual step. The helper does not upload labels.

1. The customer may add rows to the label file for servers the questionnaire did not cover. The first column must stay named `IP`.
2. The customer runs `check-labels`. It changes nothing and lists every value an upload would replace.
3. The customer uploads the file in Secure Workload under Organize > Label Management > User Defined Label Upload, with the Merge operation. Under Merge, blank cells do not erase existing labels.

A scope whose servers have no labels yet is still created. It stays empty until the labels arrive.

## The Helper

`csw_scope_helper.py` needs Python 3.8 or later and nothing else installed.

| Command | What it does | Changes the tenant |
|---|---|---|
| `export` | Saves the scope list and the tenant's label names to a file | No |
| `check-labels --labels FILE` | Compares a label file with the tenant's labels | No |
| `apply --plan FILE` | Previews everything the plan would do | No |
| `apply --plan FILE --write` | Creates the scopes after the customer types yes | Yes |
| `apply --plan FILE --write --allow-changes` | Also renames scopes and changes queries the plan approves, after a second typed yes | Yes |
| `apply --plan FILE --write --allow-removals` | Also removes scopes the plan approves, after its own typed yes | Yes |
| `undo --record FILE` | Previews the reversal of what one build did | No |
| `undo --record FILE --write` | Reverses it after the customer types yes | Yes |
| `undo --find-created --under "SCOPE"` | Lists scopes under the named scope that this tool created, for when the record file is lost | No |
| `undo --find-created --under "SCOPE" --write` | Removes those scopes, deepest first, after a typed yes that repeats the count | Yes |

Add `--under "full scope name"` to work under one scope. In a shared tenant, `export --under` saves only that scope and what is below it.

On Windows, type `py` in place of `python3`. The helper prints its "run this next" commands in the form for the computer it is running on.

| Option | What it does |
|---|---|
| `--out-dir FOLDER` | Where the helper saves its files. The default is the current folder |
| `--credentials FILE` | Reads the key and secret from a file instead of asking |
| `--ca-file FILE` | Trusts a private certificate authority, for an on-premises cluster |
| `--commit-timeout SECONDS` | How long to wait for a commit. The default is 300 |
| `--no-commit` | With `apply --write`, makes the changes and leaves them uncommitted, so the customer can look at pending query changes in Secure Workload and commit there |
| `--yes` | Skips the typed yes before creating scopes. It never covers renames, query changes, removals, or `--find-created` |
| `--version` | Prints the version |

### If A Build Is Interrupted

Run the same `apply --write` command again. When the helper finds an unfinished record file in the output folder for the same tenant, the same parent, and the same plan, it says so before asking for the typed yes and continues that record. One `undo` then reverses the whole build.

If the connection drops while a scope is being created, the helper does not blindly send the request again. It looks for the scope first, checks it if it is there, and tries once more only if it is not. The record file says which happened.

Reads are tried again up to 3 times, after waits of 2, 5, and 10 seconds, on a network error or a server error. Changes are never sent twice.

For a rename, a query change, or a removal, the helper saves the record with that item marked "attempting", with its full before values, before it sends the call. If the connection drops or the server answers with an error, the helper reads the scope back, records whether the tenant made the change, and stops. If the tenant cannot be read either, the item stays "attempting". The next `apply` run and `undo` both read the tenant first and settle every "attempting" item from what they find, so the record never says less than the tenant holds.

`undo` protects its own calls the same way. A recreate whose answer is lost looks for the scope before trying again, so a scope is never recreated twice. If an undo is interrupted, run the same undo command again.

### Order Of Work And Undo

One run works in this order: read the tenant, check every item's before against the live scope, create (parents first), rename, change queries, remove (deepest first), commit. After each change the helper reads the scope back, checks it, and saves the record. It stops at the first failure. If any scope no longer matches its before, the run stops before a single change, and the fix is a fresh export and a new plan.

`undo` works in the opposite order: recreate removed scopes with new IDs, restore queries, restore names, delete created scopes, commit. Before anything it checks that each scope still looks the way the run left it, and stops if not.

If something was attached to a scope after the build created it, the tenant refuses to remove it. `undo` then says "IN USE, not removed" with what the tenant says depends on it, leaves that scope and its parent in place, reverses everything else, and asks the customer to clear what depends on the scope and run the same undo command again.

### Commit

Creating scopes and changing queries leave changes that need a commit. A changed query is held separately until it is committed. With `--no-commit` the helper skips the commit and says so. The customer can then look at the pending changes in Secure Workload under Organize > Scopes and Inventory and select Commit Changes there. The helper asks Secure Workload to commit and wait until it finishes. If that takes longer than the commit timeout, the helper checks the scope list every 15 seconds for the same length of time. It reports "committed" when nothing in its work area is still marked changed, or says the commit is still running and to check in Secure Workload.

The helper signs in with a Secure Workload API key (32 characters) and API secret (40 characters). The customer creates the pair by following Cisco's current directions for their tenant. The long Security Cloud Control access token is a different credential and does not work. The key needs the capability `user_role_scope_management`. The two read-only commands also work with `app_policy_management`. To read what depends on each scope, `export` uses the capabilities listed under "What Depends On A Scope".

The key and secret can be typed at the prompts, given in the environment variables `CSW_API_KEY` and `CSW_API_SECRET`, or read from a file with `--credentials`. The helper never saves them.

For an on-premises cluster with a private certificate, add `--ca-file` with the certificate file. The helper has no option to skip certificate checking. `--ca-file` is tested against a local test server only. A real on-premises cluster is still untested.

### Safety Rules

Every part of the helper that can change a tenant follows these rules.

1. It previews first. It changes nothing without `--write` and a typed yes.
2. It reads the tenant before acting and stops on a conflict.
3. It changes or removes an existing scope only when the plan approves that item, the matching permission option is given, and the customer types yes at a prompt that lists it. It never touches a top-level scope or anything outside the scope it is working under.
4. It reads back every scope it creates and stops at the first mismatch.
5. It saves a record file after every single change, with before and after values, that `undo` can reverse. Every scope it creates carries the description "Created by CSW Scope Builder" and the date.
6. It commits scope changes only when every uncommitted scope change in the tenant belongs to its own work area: the parent scope, what is below it, and what is above it.
7. It never saves the API key or secret, and it refuses a plan file in a format it does not know.
8. It can only send the calls on its allow lists. Version 1.2 added one change call, the update of one scope, and three read calls for what depends on a scope.

## Design Rules

1. The children of any one scope are all defined by the same label, and every workload carries exactly one value for it. This keeps sibling scopes from overlapping.
2. The default tree is the parent scope, then Environment, then Application.
3. Shared services sit under an Environment value of Shared, with one child scope for each service.
4. A Location level is added only when a team divides its responsibility by site or cloud.
5. Regulated zones are a label. They become a level only when a separate team owns policy for a zone.
6. The tree stops at four levels below the parent scope. Cisco says to keep the tree shallow and gives no number. Four is this tool's own ceiling.
7. Applications identified by subnet get a label file, so scope queries still use labels.
8. A change to an existing scope is only ever proposed. Nothing is renamed, changed, or removed unless the consultant approves it in the plan and the customer allows it when building.
9. A level the parent scope already stands for is not built again below it.
10. Missing information does not stop the plan.

## Limits The Plan Checks

| Limit | Value | Source |
|---|---|---|
| Child scopes under one top-level scope | 1000 | Configuration Limits, release 3.9, and the platform datasheet |
| Child scopes under one parent | 999 | Configuration Limits, release 4.0 |
| Labeled addresses, SaaS | 6,000 per 100 licenses | Label Limits, release 3.10 |
| Labeled subnets, SaaS | 120 per 100 licenses | Label Limits, release 3.10 |
| Label names in a tenant | 32 | Secure Workload OpenAPIs, release 3.10 |

Child scopes are counted as scopes that have a parent, under the same top-level scope as the chosen parent. A scope list saved with `export --under` covers only part of the tenant, so the helper also saves the full count in the file. A scope list from helper 1.0 does not carry that count, and the plan says the count covers only part of the tenant.

The plan is built for Secure Workload release 3.10 and later.

## Known Limits

- Tested on macOS against a SaaS tenant. Windows file names, commands, and screen output are covered by automated tests but have not been run on a Windows computer by the maintainer. A real on-premises cluster is untested.
- Cisco's documentation does not say whether a tenant accepts two scopes under one parent whose names differ only in capital letters. A SaaS lab tenant refused the second one on 19 Nov 2026 ("must be case insensitive unique"), so this tool treats them as one scope.
- Cisco's API documentation for 3.10 and 4.0 does not mention a "too many requests" answer (429). The helper treats it like any other refusal and stops.
- A parent scope is recognized as standing for a level only when its query is one "label equals value". Other query shapes must be set by hand in the planner.
- Renames, query changes, removals, and reading what depends on a scope are tested against the simulated tenant only. They have not been run against a real tenant.
- A scope cannot be moved to a different parent, because the update call in Cisco's API does not take a parent.
- The planner proposes a rename or a query change, never both for one scope. A scope that differs in both name and query is treated as new.
- The export reads workspaces, inventory filters, and roles. Other things can depend on a scope, such as policies. For those the tenant's own refusal at removal time is the only check.
- A role is listed against the scope it is defined under. Roles that are only granted access to a scope are not listed.
- Undo recreates a removed scope with its name, query, and description. It does not restore anything else that was attached to it.
- 3.10 as the oldest supported release is inferred from Cisco's August 2026 hardening advisory and release notes. No Cisco bulletin was found that states it.
- On-premises label limits are not checked.
- Subnet overlap checking covers IPv4 only.
- Kubernetes and OpenShift workloads are flagged and left out. Plan those by namespace.
- Label upload is manual.
- Cisco's 3.10 and 4.0 user guides describe creating the API key inside Secure Workload. On some tenants it is created elsewhere, so this README does not give a click path.

## Running The Tests

```
npm install jsdom
python3 tests/run_all.py
```

It runs the three test files and prints one `ALL PASS`, or the failures. The tests use a simulated tenant and never touch a real one.

No certificate or private key is kept in this repository. The `--ca-file` test makes a throwaway certificate with the `openssl` command each time it runs, in a temporary folder it deletes afterward. If `openssl` is not installed, that one test is skipped and a line starting with `SKIPPED` says so.

## References

- Scope Design Principles: https://securitydocs.cisco.com/docs/csw/3-10/user/91653.dita
- General Process For Implementing Microsegmentation: https://securitydocs.cisco.com/docs/csw/3-10/user/92156.dita
- Configuration Limits, release 3.9: https://www.cisco.com/c/en/us/td/docs/security/workload_security/secure_workload/user-guide/3_9/cisco-secure-workload-user-guide-on-prem-v39/configuration-limits-in-secure-workload.html
- Secure Workload Platform Datasheet: https://www.cisco.com/c/en/us/products/collateral/data-center-analytics/tetration-analytics/cisco-secure-workload-dsv3a.html
- Label Limits: https://securitydocs.cisco.com/docs/csw/3-10/user/91705.dita
- Guidelines For Uploading Label Files: https://securitydocs.cisco.com/docs/csw/3-10/user/91685.dita
- Scope-Dependent Label APIs: https://securitydocs.cisco.com/docs/csw/3-10/user/92071.dita
- Scopes API: https://securitydocs.cisco.com/docs/csw/3-10/user/92075.dita
- Commit Changes: https://securitydocs.cisco.com/docs/csw/3-10/user/91587.dita
- Secure Workload OpenAPIs, release 4.0 SaaS (scopes: update, delete and its 422 answer, commit with `sync`; workspaces; inventory filters; roles; filter types): https://www.cisco.com/c/en/us/td/docs/security/workload_security/secure_workload/user-guide/4_0/cisco-secure-workload-user-guide-saas-v40/m-openapi.html
- Secure Workload OpenAPIs, release 3.10 on-premises (the same sections): https://www.cisco.com/c/en/us/td/docs/security/workload_security/secure_workload/user-guide/3_10/cisco-secure-workload-user-guide-on-prem-v310/secure-workload-openapis.html
- Label keys and values are not case sensitive, release 3.10: https://securitydocs.cisco.com/docs/csw/3-10/user/91627.dita
- Label keys and values are not case sensitive, release 4.0 SaaS: https://www.cisco.com/c/en/us/td/docs/security/workload_security/secure_workload/user-guide/4_0/cisco-secure-workload-user-guide-saas-v40/m-inventory.html

Ctrl+F keywords: quick start, before you start, full commands, export, check-labels, apply, write, undo, scope tree, scope design principles, build under, parent scope stands for, anchor, capital letters, changes to existing scopes, rename, change query, remove, approve, allow-changes, allow-removals, no-commit, attempting, by hand, in use, depends on, may already exist as, find-created, interrupted build, commit timeout, ca-file, label names, label file, check-labels, merge, apply, undo, record file, later round, blocker, configuration limits.
