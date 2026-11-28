# Bomb Squad and GuardDog on the same packages

Every figure here comes from one of three benchmark runs on `main`, two on 2026-11-27 and one on 2026-11-28, all on the same dataset commit. The pins are in [Runs](#runs). The third, run [46090723283](https://github.com/danielguillaumont/bomb-squad/actions/runs/46090723283), measured [updates and detonation](#updates-and-detonation-of-the-benign-packages) on the benign packages.

- **Held-out sample:** GitHub Actions run [46075004726](https://github.com/danielguillaumont/bomb-squad/actions/runs/46075004726), Bomb Squad 2.0.1 at commit `4562013`. Its 400 malicious and 400 benign packages share none with the development runs. Its protocol was [fixed before it ran](../methodology.md#how-the-benchmark-works). [Its results](#held-out-sample) are the less in-sample measure.
- **Development sample:** run [46066816294](https://github.com/danielguillaumont/bomb-squad/actions/runs/46066816294), at commit `63c1026`, on the same 400 and 400 packages as the [development runs](#development-runs) whose rule counts shaped the rules. [Its results](#development-sample) are in-sample.

## What was measured

Both tools read the same unpacked packages and neither runs them. Bomb Squad runs `scan --package`, as `bombsquad diff` reviews a release. GuardDog 3.2.0 runs its local scan, which uses its source-code rules; its registry-metadata rules need package metadata and do not run.

- **Malicious:** 200 npm and 200 PyPI samples per run from the DataDog malicious-software-packages-dataset, one version per package name. The development sample uses seed 2026. The held-out sample uses seed 2027 and leaves out every package the development runs chose.
- **Benign:** 200 npm and 200 PyPI packages per run, sampled from the 1,000 most-downloaded in each ecosystem, each at its highest release published on or before the dataset commit's date. The held-out sample draws from the 800 that the development runs did not use. Releases over the 100 MB download limit are left out, so the PyPI benign denominator is 197 in the held-out sample and 195 in the development sample.
- **Detectors:** Bomb Squad at a high finding, and at a review or high finding. GuardDog at its risk label `high_risk`, at `suspicious` or `high_risk`, and at any matched rule, which is what its exit code reports.

Neither tool timed out or crashed on any package in either run. [Methodology](../methodology.md#how-the-benchmark-works) describes the harness. All packages are in the retrospective set: the dataset commit predates the cutoff, so the after-cutoff set is empty (see [What neither number shows](#what-neither-number-shows)).

## Held-out sample

| Ecosystem | Detector | Recall | False positives | Per 1,000 benign |
|---|---|---|---|---|
| npm | Bomb Squad, a high finding | 5.0% (10/200) | 0.5% (1/200) | 5.0 |
| npm | Bomb Squad, a review or high finding | 53.0% (106/200) | 3.0% (6/200) | 30.0 |
| npm | GuardDog, high risk | 65.0% (130/200) | 0.0% (0/200) | 0.0 |
| npm | GuardDog, suspicious or high risk | 70.0% (140/200) | 0.5% (1/200) | 5.0 |
| npm | GuardDog, any rule (its exit code) | 84.0% (168/200) | 40.0% (80/200) | 400.0 |
| PyPI | Bomb Squad, a high finding | 50.0% (100/200) | 1.5% (3/197) | 15.2 |
| PyPI | Bomb Squad, a review or high finding | 71.5% (143/200) | 8.6% (17/197) | 86.3 |
| PyPI | GuardDog, high risk | 86.5% (173/200) | 9.1% (18/197) | 91.4 |
| PyPI | GuardDog, suspicious or high risk | 88.5% (177/200) | 14.7% (29/197) | 147.2 |
| PyPI | GuardDog, any rule (its exit code) | 97.5% (195/200) | 82.7% (163/197) | 827.4 |

GuardDog finds more malicious packages at every pair of thresholds, in both ecosystems, as in the development sample. On npm it also flags fewer popular releases: 0.5% (1/200) at suspicious or high risk, against Bomb Squad's 3.0% (6/200) at review or high. On PyPI, Bomb Squad flags fewer: 8.6% (17/197) against 14.7% (29/197).

Both tools score higher on npm here than in the development sample (Bomb Squad 53.0% against 45.0%, GuardDog 70.0% against 66.0%). So the difference between the two samples is not only Bomb Squad's tuning: the samples differ too, and 200 packages is a small sample.

**Restricted to packages where Bomb Squad found an install-time entry point:**

| Ecosystem | Packages | Bomb Squad, high | Bomb Squad, review or high | GuardDog, high risk | GuardDog, suspicious or high risk |
|---|---|---|---|---|---|
| npm (an npm lifecycle script or `binding.gyp`) | 125 | 8.0% (10/125) | 84.8% (106/125) | 73.6% (92/125) | 80.8% (101/125) |
| PyPI (a Python entry point) | 185 | 54.1% (100/185) | 77.3% (143/185) | 90.3% (167/185) | 92.4% (171/185) |

**The tools miss different packages.** At review or high (Bomb Squad) against suspicious or high risk (GuardDog):

| Ecosystem | Both | Bomb Squad only | GuardDog only | Neither | Either tool, recall | Either tool, false positives |
|---|---|---|---|---|---|---|
| npm | 88 | 18 | 52 | 42 | 79.0% (158/200) | 3.0% (6/200) |
| PyPI | 136 | 7 | 41 | 16 | 92.0% (184/200) | 19.3% (38/197) |

**The same PyPI pattern recurs.** 76 of the 200 PyPI samples have the findings of the 64 in the development sample: an encoded PowerShell command, downloading and evaluating code, run from install. All 76 are dated February to May 2023 in the dataset. Both tools flag all 76, so this sample is held out by package but not by campaign. On the other 124:
- Bomb Squad finds 19.4% (24/124) at a high finding and 54.0% (67/124) at review or high;
- GuardDog finds 78.2% (97/124) at high risk and 81.5% (101/124) at suspicious or high risk.

**Where Bomb Squad loses here:**
- **No install-time entry point found:** 73 npm and 15 PyPI samples, none of which Bomb Squad flags. GuardDog labels 50.7% (37/73) and 40.0% (6/15) of them high risk.
- **An entry point, but nothing above info:** 21 npm and 42 PyPI samples. 6 and 27 of them have no finding at all; the rest have only info findings, among them BS-PRC-001 in 14 of the 15 other npm samples and all 15 other PyPI samples.
- **npm severity:** 91 of Bomb Squad's 106 npm detections rest only on BS-NET-003 at review. This time one popular npm release has that finding too: esbuild 0.28.2, whose `postinstall` script downloads its platform binary from the npm registry when the optional dependency that holds it is missing.
- **False positives at review or high:**
  - npm, 6: invisible characters (BS-UC-001) in 5, and esbuild's network access;
  - PyPI, 17: invisible characters in 6, code that runs at every Python start (BS-EP-001) in 6, text evaluated as code (BS-DE-006) in 5, network access (BS-NET-003) in 4, and the whole environment collected (BS-ENV-001) in 1. A package can have several.

  Four are at high, and all four were checked by hand. No code is hidden in any of them:
  - **iconv-lite** (npm), BS-UC-001: private-use and zero-width characters in its generated character-set tables, which are data.
  - **django** (PyPI), BS-UC-001: direction-changing and zero-width characters inside the Unicode ranges of the vendored, minified XRegExp.
  - **onnxruntime** (PyPI), BS-OB-001: an ASCII diagram in a docstring, with an arrow head and a bar 113 spaces in. The narrowed rule still counts these as code, because they are a word and an operator.
  - **ansible-core** (PyPI), BS-EX-001: Bomb Squad took `ansible/modules/setup.py`, Ansible's fact-gathering module, for a build script. Neither pip nor `python setup.py` runs it, so this is a fault in Bomb Squad, not only a noisy rule.

  These were found after the held-out run. The ansible-core fault was fixed afterwards: in a package, a `setup.py` below the project root is now reported at info. The figures above are from before the fix, and the fix makes this sample in-sample for it, so a later measure needs a new sample.

## Development sample

| Ecosystem | Detector | Recall | False positives | Per 1,000 benign |
|---|---|---|---|---|
| npm | Bomb Squad, a high finding | 6.0% (12/200) | 0.0% (0/200) | 0.0 |
| npm | Bomb Squad, a review or high finding | 45.0% (90/200) | 1.5% (3/200) | 15.0 |
| npm | GuardDog, high risk | 59.5% (119/200) | 1.0% (2/200) | 10.0 |
| npm | GuardDog, suspicious or high risk | 66.0% (132/200) | 2.0% (4/200) | 20.0 |
| npm | GuardDog, any rule (its exit code) | 84.5% (169/200) | 36.0% (72/200) | 360.0 |
| PyPI | Bomb Squad, a high finding | 40.5% (81/200) | 3.1% (6/195) | 30.8 |
| PyPI | Bomb Squad, a review or high finding | 65.5% (131/200) | 11.8% (23/195) | 117.9 |
| PyPI | GuardDog, high risk | 88.5% (177/200) | 10.3% (20/195) | 102.6 |
| PyPI | GuardDog, suspicious or high risk | 91.0% (182/200) | 15.9% (31/195) | 159.0 |
| PyPI | GuardDog, any rule (its exit code) | 96.5% (193/200) | 86.2% (168/195) | 861.5 |

GuardDog finds more malicious packages than Bomb Squad at every pair of thresholds, in both ecosystems. Its exit code flags 36.0% of popular npm releases and 86.2% of popular PyPI releases, so its risk labels are the fair comparison.

**Restricted to packages where Bomb Squad found an install-time entry point**, the comparison Bomb Squad is built for:

| Ecosystem | Packages | Bomb Squad, high | Bomb Squad, review or high | GuardDog, high risk | GuardDog, suspicious or high risk |
|---|---|---|---|---|---|
| npm (an npm lifecycle script or `binding.gyp`) | 114 | 10.5% (12/114) | 78.9% (90/114) | 64.9% (74/114) | 73.7% (84/114) |
| PyPI (a Python entry point, such as `setup.py`, a build backend or a `.pth` file) | 176 | 46.0% (81/176) | 74.4% (131/176) | 92.6% (163/176) | 94.9% (167/176) |

**The tools miss different packages.** At review or high (Bomb Squad) against suspicious or high risk (GuardDog):

| Ecosystem | Both | Bomb Squad only | GuardDog only | Neither | Either tool, recall | Either tool, false positives |
|---|---|---|---|---|---|---|
| npm | 70 | 20 | 62 | 48 | 76.0% (152/200) | 2.5% (5/200) |
| PyPI | 126 | 5 | 56 | 13 | 93.5% (187/200) | 23.1% (45/195) |

**One pattern carries much of the PyPI recall.** 64 of the 200 PyPI samples, all dated February or March 2023 in the dataset, have the same Bomb Squad findings: an encoded PowerShell command, downloading and evaluating code, run from install. Both tools flag all 64. On the other 136, Bomb Squad's recall is 12.5% (17/136) at a high finding and 49.3% (67/136) at review or high, and GuardDog's is 83.1% (113/136) at high risk and 86.8% (118/136) at suspicious or high risk.

### Where Bomb Squad loses in the development sample

- **Payloads that run on import or require.** 84 npm and 24 PyPI samples have no install-time entry point that Bomb Squad found, and Bomb Squad flags none of them. GuardDog labels 53.6% (45/84) of those npm samples and 58.3% (14/24) of those PyPI samples high risk.
- **Install-time code with nothing above info.** Of the samples where Bomb Squad found an entry point, it reports nothing at review or high for 26 npm and 45 PyPI samples. 13 of those npm samples and 25 of those PyPI samples have no finding at all. The rest have only info findings, among them BS-PRC-001, "Starts other programs", in 12 of the 13 other npm samples and 19 of the 20 other PyPI samples.
- **npm severity.** Bomb Squad rates few npm samples high: 6.0% (12/200). 72 of its 90 npm detections rest only on BS-NET-003, "Opens network connections", at review. No benign npm release in this sample has that finding at review or high, but a reviewer still has to read the code to tell the two apart.
- **PyPI false positives.** At review or high, Bomb Squad flags 23 of 195 popular PyPI releases:
  - invisible or direction-changing characters (BS-UC-001) in 9;
  - text evaluated as code (BS-DE-006) in 6, network access (BS-NET-003) in 5, and code that runs at every Python start (BS-EP-001) in 4, such as setuptools' `.pth` file;
  - packed or obfuscated code (BS-OB-002) in 2;
  - a package can have several.

  Six are at high. Three are invisible characters in pylint, jupyterlab and jupyterlab-widgets. Two are BS-OB-001, "Hides code after a long run of whitespace", and were checked by hand:
  - in uv, the padding is a test snapshot of an error caret;
  - in google-cloud-firestore, it is a docstring line wrapped after 534 spaces.

  No code is hidden in either. The sixth is BS-EX-001 in nodeenv: its `setup.py` imports the module, and that module both opens network connections and names `.npmrc` in a shell template.
- **npm false positives:** three, all invisible characters (BS-UC-001), in recharts, vite and date-fns.

## Where the comparison favours one tool

- **Selection.** The DataDog README says most of its samples were found by GuardDog. Samples GuardDog missed are less likely to be in the dataset, so its recall here is an upper estimate.
- **Scope.** Bomb Squad reports what runs without anyone choosing to run it: install hooks, `.pth` files, build backends and the code they reach. A package whose payload runs when it is imported or required, and not on install, has no entry point for Bomb Squad and is a miss here by design. GuardDog reads every file.
- **Rules seen.** Bomb Squad's rules changed after the development runs listed below, which used the development sample's packages, so that sample's figures are in-sample for Bomb Squad. The changes were made from rule counts and error lines, and from benign packages inspected by hand, not from reading malicious samples. No rule changed between the held-out run and its figures being published. Two later fixes changed what package mode counts as run on install: a `setup.py` below the project root ([pull request 38](https://github.com/danielguillaumont/bomb-squad/pull/38)) and npm `prepare` scripts ([pull request 43](https://github.com/danielguillaumont/bomb-squad/pull/43)). The held-out figures are from before both. The held-out packages were not used before that run, but near-identical packages of one campaign fall in both samples, such as the 76 and 64 PyPI samples above. GuardDog 3.2.0 was published to PyPI on 2026-08-12, before this dataset commit. GuardDog and the dataset both come from DataDog.
- **Precision** depends on the ratio of malicious to benign packages here, which is not the ratio in the wild. False positives per 1,000 benign releases do not. The run's `scores.md` gives precision on this mix.

## What neither number shows

- No findings does not mean safe, for either tool.
- Static analysis does not see code fetched after install, payloads gated on time or environment, or behaviour that only shows at run time.
- A popular release is assumed benign. A compromised release in the benign sample would count as a false positive.
- The after-cutoff split, packages DataDog found after the rules were frozen, is empty for this dataset commit. It is the measure of detection of the unknown, and it needs a later dataset commit.
- 200 packages per ecosystem is a small sample: a difference of a few packages is a difference of one or two percentage points.

## Updates and detonation of the benign packages

Run [46090723283](https://github.com/danielguillaumont/bomb-squad/actions/runs/46090723283) on `main` (started 2026-11-28T00:59:03Z, Bomb Squad 2.0.1 at commit `ea87b2b`) used the development sample's pins and packages, with version pairs and with detonation of the benign packages only. No malicious package was detonated, so detonation's recall is not measured.

Its static figures match the development sample's above, except for Bomb Squad's PyPI false positives. There it has 4 rather than 6 at high, and 20 rather than 23 at review. The difference is three packages, from two changes made after the development sample ran:

- google-cloud-firestore and uv lost their BS-OB-001 finding when that rule was narrowed in [pull request 34](https://github.com/danielguillaumont/bomb-squad/pull/34).
- pyzmq's BS-NET-003 finding came from `examples/cython/setup.py`, which is below the project root. Since [pull request 38](https://github.com/danielguillaumont/bomb-squad/pull/38), such a `setup.py` is reported at info.

GuardDog labelled every package the same in both runs.

### Updates

Each benign release was diffed with `bombsquad diff` against the highest lower version published before it, as the pull-request gate reviews an update. On an ordinary update every alarm is a false alarm.

| Ecosystem | Alarm | False alarms | Per 1,000 updates |
|---|---|---|---|
| npm | A new review or high finding | 0.5% (1/199) | 5.0 |
| npm | A new high finding | 0.0% (0/199) | 0.0 |
| npm | A new or changed entry point that installing runs | 0.0% (0/199) | 0.0 |
| npm | A new finding, or a publish signal at review | 14.1% (28/199) | 140.7 |
| PyPI | A new review or high finding | 2.1% (4/194) | 20.6 |
| PyPI | A new high finding | 1.0% (2/194) | 10.3 |
| PyPI | A new or changed entry point that installing runs | 0.0% (0/194) | 0.0 |
| PyPI | A new finding, or a publish signal at review | 3.6% (7/194) | 36.1 |

- **Denominators:** one release in each ecosystem had no earlier release. The 5 PyPI releases over the download limit are left out, as above. No diff failed.
- **New findings:** BS-UC-001 (invisible characters) in 1 npm and 3 PyPI updates, 2 of them at high, and BS-NET-003 in 1 PyPI update.
- **Publish signals:** on npm, 27 updates raised only a signal: a new publisher in 16, a maintainer change in 11 and a changed repository in 8, some with more than one. On PyPI, 3 updates changed their declared repository. PyPI does not publish uploaders, so it has no publisher signal.
- **Entry points listed but not run:** 8 npm and 26 PyPI updates added or changed workflows, git hooks, agent files, `conftest.py` in sdists, or npm `prepare` scripts. Installing runs none of them, so they are not counted as alarms.
- **Time:** the median diff took 0.2 seconds on npm and 1.1 seconds on PyPI, fetching both releases included.

### Detonation

| Ecosystem | Detonated | Errors or timeouts | Installed nothing | Wheel instead of sdist | Median seconds | Total seconds |
|---|---|---|---|---|---|---|
| npm | 200 | 0 | 0 | n/a | 2.7 | 547.2 |
| PyPI | 195 | 0 | 1 | 51 | 4.0 | 995.3 |

- **Flagged** (package code read or sent a fake credential, or wrote somewhere that persists): 0 of 200 npm and 0 of 195 PyPI packages.
- **Anything observed:** 0 of 200 npm and 5 of 195 PyPI packages. Four made network attempts, which only the sink answered, and four started a program.
  - The static scan predicted reportlab's network attempts (BS-NET-003 at review). The other three are gaps in the static rules.
  - It predicted two of the programs started (BS-PRC-001 at info). The other two are gaps.
  - The packages were not inspected further, so this is what was observed, not an explanation of it.
- **npm:** according to the registry metadata, none of the 200 releases has a `preinstall`, `install` or `postinstall` script, or a `binding.gyp`, so detonation ran none of their code. 22 have a `prepare` script, which a registry install does not run.
- **PyPI:** 51 sdists did not build in the sandbox, which reaches no package index and has only its preinstalled build backends, so the release's wheel was installed and imported instead. One package, mysqlclient, installed neither way: its sdist did not build, and the wheel tried after it did not install.
- **TLS:** in this run the sink recorded TLS by server name only, so a fake credential sent over HTTPS would have counted as read, not as sent. The sink has read TLS since.
- **Dependencies:** in this run no dependency was installed, so package code that loads one failed when it did. Detonation has installed declared dependencies since.

## Development runs

Before any figure was used, the first runs on a branch found faults in the harness and in Bomb Squad, fixed in [pull request 30](https://github.com/danielguillaumont/bomb-squad/pull/30):

| Run | What it showed | Fix |
|---|---|---|
| 46052046868 | GuardDog counted as flagging on any matched rule, including capability rules such as "opens network connections". Five malicious samples unpacked to nothing: their member names cannot exist on Windows and were skipped. Most PyPI misses were `setup.py` running a command that Bomb Squad noted only as a process start. | GuardDog scored by its risk label as well. Unportable names renamed instead of skipped. Literal commands in Python and JavaScript process calls analysed as shell; local Python imports followed. |
| 46055333444 | A Bomb Squad crash was scored as a clean scan. Workflows, git hooks, agent settings and `conftest.py` shipped in sdists made most benign PyPI false positives. Flag emoji, in-word zero-width non-joiners and Markdown table padding were reported. | Output without a result counts as an error. Package mode. The three text patterns narrowed. A file with a mismatched byte order mark no longer stops the scan. |
| 46060295931 | Two malicious npm samples stopped the PowerShell parser: a malformed assembly-qualified type name throws on .NET. Benign `setup.py` files ran their own version file with `exec`. | Type names fall back safely and one document cannot fail the others. `exec` of a local file follows that file. |
| 46063110536 | Failed before scanning: GitHub's unauthenticated API rate limit. | The list is fetched with the job's token. |
| 46063849521 | Workflow-wide settings and unreferenced PowerShell files in packages were still scored. | Package mode covers them. |
| 46065152646 | No errors from either tool. | None before this run. Its scores are the same as the run on `main`, which ran the same code. |

The two BS-OB-001 false positives in the development sample were found after these runs. The rule was narrowed in [pull request 34](https://github.com/danielguillaumont/bomb-squad/pull/34) before the held-out run, so the development sample's figures are those of the earlier rule.

### After the held-out run

Run 46085706292 (2026-11-28, `main` at `1c829e374a24`, seed 2026) was the first with detonation of the benign packages and with version pairs. Its figures are not used. It showed two faults, fixed in the pull request that added this paragraph:

- **`prepare` scripts:** 22 of the 200 benign npm packages have one, and detonation ran none of them, because npm runs `prepare` for a local or git install, not for a package from the registry. Package mode had treated them as run on install. It no longer does. This changes Bomb Squad's scan after the held-out run, so the held-out and development figures above are those of the earlier code.
- **Entry points in the diff:** most new or changed PyPI entry points were workflows and git hooks shipped in sdists, which installing does not run. The diff's entry point threshold now counts only those that installing runs.

It also showed that 52 of the 195 PyPI detonations installed nothing: pip could not build the sdist without its build dependencies. The scores now count these, and the sandbox now installs the release's wheel when the sdist does not build ([pull request 44](https://github.com/danielguillaumont/bomb-squad/pull/44)). The run after both fixes, [46090723283](https://github.com/danielguillaumont/bomb-squad/actions/runs/46090723283), gave every one of the 800 packages the same Bomb Squad levels as this run.

**Correction:** earlier versions of this page and the README showed 79.0% for 90/114. The scorer rounded each rate to four decimals and then again to one, and 90/114 is 78.9%. The scorer now formats rates from their counts. Every other percentage on this page was checked against its counts.

## Runs

All three runs use `.github/workflows/benchmark.yml` on `main`, with the same pins:
- **GuardDog:** 3.2.0, with its dependencies as of 2026-11-20.
- **Malicious:** DataDog/malicious-software-packages-dataset at commit `72c723be547033c558244520524b117c8d71663b` (2026-11-05), 200 per ecosystem.
- **Benign:** `npm-high-impact` 1.13.0 and hugovk/top-pypi-packages at commit `29c0d4c38c28` (2026-11-01), from the top 1,000, 200 per ecosystem, releases as of 2026-11-05.
- **Kept:** each run's artifact holds package names, versions, rule IDs, levels and timings, not sample content. The updates run also keeps detonation categories and counts, and for each update the counts of entry points, the rule IDs and the signal names. The workflow keeps each artifact for 90 days.

| | Held-out sample | Development sample | Updates and detonation |
|---|---|---|---|
| Run | 46075004726, started 2026-11-27T22:11:06Z | 46066816294, started 2026-11-27T20:55:11Z | 46090723283, started 2026-11-28T00:59:03Z |
| Bomb Squad | 2.0.1 at `45620136314441e1fa5f89c57c1e281a3fb760f8` | 2.0.0.dev0 at `63c102626739ad14f0e009c4fadcf065333e363b` | 2.0.1 at `ea87b2b785c2eec97195653f52a47777302d7038` |
| Seed | 2027, leaving out the packages of seed 2026 at 200 and at 5 | 2026 | 2026 |
| Cutoff | 2026-11-27, the commit's date | 2026-11-27, the commit's date | 2026-11-27, the commit's date |
| Inputs | | | `version-pairs` on, `detonate` benign, 60 seconds each |
