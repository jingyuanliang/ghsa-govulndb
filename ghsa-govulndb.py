#!/usr/bin/env python3

import argparse
import json
import os
import os.path

parser = argparse.ArgumentParser()
parser.add_argument('--ghsa', required=True)
parser.add_argument('--govulndb', required=True)
args = parser.parse_args()

outs = {}
modified = ''
vulnz = {}
vulnids = {}

for root, dirs, files in os.walk(args.ghsa):
  for fn in files:
    path = os.path.join(root, fn)
    print(path)
    with open(path) as f:
      j = json.load(f)
      for affected in j['affected']:
        if affected['package']['ecosystem'] != 'Go':
          continue
        for r in affected.get('ranges', []):
          if r['type'] != 'ECOSYSTEM':
            continue
          fixed = None
          for event in r['events']:
            fixed = event.get('fixed') or fixed
          pkg = vulnz.setdefault(affected['package']['name'], [])
          vuln = {
              'id': j['id'],
              'modified': j['modified'],
          }
          if fixed:
            vuln['fixed'] = fixed
          pkg.append(vuln)
          modified = max(modified, j['modified'])
          vulnids[j['id']] = j['modified']

outs['index/db.json'] = {
    'modified': modified,
}

outs['index/modules.json'] = []
for pkg, vulns in vulnz.items():
  outs['index/modules.json'].append({
      'path': pkg,
      'vulns': vulns,
  })

outs['index/vulns.json'] = []
for vulnid, modified in vulnids.items():
  outs['index/vulns.json'].append({
      'id': vulnid,
      'modified': modified,
      'aliases': [],
  })
  outs['ID/{}.json'.format(vulnid)] = {
      'schema_version': '1.3.1',
      'id': vulnid,
      'modified': modified,
  }

for fn, obj in outs.items():
  path = os.path.join(args.govulndb, fn)
  os.makedirs(os.path.dirname(path), exist_ok=True)
  with open(path, 'w') as f:
    json.dump(obj, f)
