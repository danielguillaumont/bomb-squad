# Bomb Squad and GuardDog on the same packages

Every figure here comes from one benchmark run: GitHub Actions run [46066816294](https://github.com/danielguillaumont/bomb-squad/actions/runs/46066816294), started 2026-11-27 on `main` at commit `63c1026`. The pins are in [Run](#run).

## What was measured

Both tools read the same unpacked packages and neither runs them. Bomb Squad runs `scan --package`, as `bombsquad diff` reviews a release. GuardDog 3.2.0 runs its local scan, which uses its source-code rules; its registry-metadata rules need package metadata and do not run.

- **Malicious:** 200 npm and 200 PyPI samples from the DataDog malicious-software-packages-dataset, one version per package name, sampled with seed 2026.
- **Benign:** 200 npm and 200 PyPI packages sampled from the 1,000 most-downloaded in each ecosystem, each at its highest release published on or before the dataset commit's date. Five PyPI releases are over the 100 MB download limit and are left out (`torch`, `claude-agent-sdk` and three NVIDIA CUDA packages), so the PyPI benign denominator is 195.
- **Detectors:** Bomb Squad at a high finding, and at a review or high finding. GuardDog at its risk label `high_risk`, at `suspicious` or `high_risk`, and at any matched rule, which is what its exit code reports.

Neither tool timed out or crashed on any package. [Methodology](../methodology.md#how-the-benchmark-works) describes the harness.

## Results

All packages are in the retrospective set: the dataset commit predates the cutoff, so the after-cutoff set is empty (see [What neither number shows](#what-neither-number-shows)).

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
| npm (an npm lifecycle script or `binding.gyp`) | 114 | 10.5% (12/114) | 79.0% (90/114) | 64.9% (74/114) | 73.7% (84/114) |
| PyPI (a Python entry point, such as `setup.py`, a build backend or a `.pth` file) | 176 | 46.0% (81/176) | 74.4% (131/176) | 92.6% (163/176) | 94.9% (167/176) |

**The tools miss different packages.** At review or high (Bomb Squad) against suspicious or high risk (GuardDog):

| Ecosystem | Both | Bomb Squad only | GuardDog only | Neither | Either tool, recall | Either tool, false positives |
|---|---|---|---|---|---|---|
| npm | 70 | 20 | 62 | 48 | 76.0% (152/200) | 2.5% (5/200) |
| PyPI | 126 | 5 | 56 | 13 | 93.5% (187/200) | 23.1% (45/195) |

**One pattern carries much of the PyPI recall.** 64 of the 200 PyPI samples, all dated February or March 2023 in the dataset, have the same Bomb Squad findings: an encoded PowerShell command, downloading and evaluating code, run from install. Both tools flag all 64. On the other 136, Bomb Squad's recall is 12.5% (17/136) at a high finding and 49.3% (67/136) at review or high, and GuardDog's is 83.1% (113/136) at high risk and 86.8% (118/136) at suspicious or high risk.

## Where Bomb Squad loses

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
- **Rules seen.** Bomb Squad's rules changed after the development runs listed below, which used the same retrospective samples, so these figures are in-sample for Bomb Squad. The changes were made from rule counts and error lines, and from benign packages inspected by hand, not from reading malicious samples. GuardDog 3.2.0 was published to PyPI on 2026-08-12, before this dataset commit. GuardDog and the dataset both come from DataDog.
- **Precision** depends on the ratio of malicious to benign packages here, which is not the ratio in the wild. False positives per 1,000 benign releases do not. The run's `scores.md` gives precision on this mix.

## What neither number shows

- No findings does not mean safe, for either tool.
- Static analysis does not see code fetched after install, payloads gated on time or environment, or behaviour that only shows at run time.
- A popular release is assumed benign. A compromised release in the benign sample would count as a false positive.
- The after-cutoff split, packages DataDog found after the rules were frozen, is empty for this dataset commit. It is the measure of detection of the unknown, and it needs a later dataset commit.
- 200 packages per ecosystem is a small sample: a difference of a few packages is a difference of one or two percentage points.

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

The two BS-OB-001 false positives above were found after these runs and are not fixed here, so they stay in the figures.

## Run

- **Run:** GitHub Actions run 46066816294, `.github/workflows/benchmark.yml`, started 2026-11-27T20:55:11Z on `main`.
- **Bomb Squad:** 2.0.0.dev0 at commit `63c102626739ad14f0e009c4fadcf065333e363b`. Cutoff 2026-11-27, the commit's date.
- **GuardDog:** 3.2.0, with its dependencies as of 2026-11-20.
- **Malicious:** DataDog/malicious-software-packages-dataset at commit `72c723be547033c558244520524b117c8d71663b` (2026-11-05), seed 2026, 200 per ecosystem.
- **Benign:** `npm-high-impact` 1.13.0 and hugovk/top-pypi-packages at commit `29c0d4c38c28` (2026-11-01), the top 1,000, 200 per ecosystem, releases as of 2026-11-05.
- **Kept:** the run's artifact holds package names, versions, rule IDs, levels and timings, not sample content. The workflow keeps it for 90 days.
