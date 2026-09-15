# TODO — UX for newer detection engineers

Ranked by impact-to-effort. Items 1–3 are each ~1 hour in the existing egui code,
4–6 an evening, 7 a real feature.

## 1. Plain-English filter summary before Run
- [ ] Live label above the Run button that reads back the effective filter, e.g.
  `Keep rules that reference (Windows logs OR SigninLogs OR pan:traffic) AND mention (APT28 or its malware)`
- [ ] Update as checkboxes change; show "No filters — everything is kept" when empty.
- Why: the three OR'd targeting dimensions + AND'd APT filter are invisible;
  this removes all guessing about what a selection actually does.

## 2. Preview counts / dry run  ✅ (live counts + report; no separate preview pass)
- [x] Live "kept N of M" with per-reason drops shown during the run (the pipeline
  clones fresh each run, so counts are gathered as files pass the filter rather
  than in a separate preview pass).
- [x] Break down drops by reason: source / actor / technique / unreadable.
- [x] Post-run: write `filter_report.txt` (filters applied + counts) to the output folder.
- Note: a true pre-download "Preview" would need a persistent rule cache; revisit
  if repos are ever cached locally between runs.

## 3. Mismatch guardrails  ✅
- [x] Warn when Splunk sourcetypes are selected but neither Splunk nor QRadar is checked.
- [x] Warn when Azure tables are selected but none of Sigma/Splunk/QRadar is checked.
- [x] Warn when APT custom terms are all blacklisted/too short (filter ends up empty).
- Note: warnings render above the filter summary; they inform, they don't block Run.

## 4. Stack presets + save/load
- [ ] 4–5 one-click presets that set tools + sources + tables/sourcetypes together:
  - Sentinel shop (Sigma + Splunk/KQL, Entra + Defender XDR tables)
  - Splunk + Windows + Palo Alto
  - Windows endpoint only (Sigma + Sysmon + Yara)
  - Network/IDS (Suricata + Zeek sourcetypes)
- [ ] Save/load current selections to JSON (repeatable monthly re-pulls).
- Why: juniors don't know which of 130 tables they ingest, but they know
  "we're a Sentinel shop with Defender XDR".

## 5. Sigma status filter (quality tier)
- [ ] Parse `status:` from Sigma YAML; default keep = stable + test,
  experimental/unsupported/deprecated behind a checkbox.
- Why: deploying experimental rules → false-positive flood → distrust of the
  whole rule-pack approach.

## 6. Generated README in the output folder
- [ ] Per run, write a README.md: filters applied, counts per tool, and 2–3 lines
  per format on deployment (Sigma needs conversion via sigma-cli; Suricata rules
  path; Sysmon `sysmon -c config.xml`; Splunk savedsearches; QRadar import).
- Why: the tool ends where a junior's real problem starts ("now what?").

## 7. Built-in Sigma conversion (bigger lift)
- [ ] Shell out to sigma-cli/pySigma to emit ready-to-paste SPL or KQL for the
  selected backend; collapse download → convert → deploy into one step.
- [ ] Map datamodel references (Endpoint.Processes etc.) to sourcetypes so
  Splunk Security Content rules survive the sourcetype filter.
- Why: juniors can't use raw Sigma YAML; paste-able queries are the deliverable.
