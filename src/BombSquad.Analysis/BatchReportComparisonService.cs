using System.Collections.Immutable;
using System.Text.Json;

namespace BombSquad.Analysis;

/// <summary>
/// Report comparison never reads, parses, or executes the original PowerShell scripts.
/// Paths are identities from reports, not instructions to access the filesystem.
/// </summary>
public enum ComparedFileStatus
{
    Compared,
    OnlyInBaseline,
    OnlyInCurrent,
    Indeterminate
}

public enum FindingChangeKind
{
    NewlyDetected,
    StillDetected,
    NoLongerDetected
}

/// <summary>
/// Count represents occurrences of the same rule ID and exact evidence text.
/// Locations are intentionally excluded: moving unchanged source is not a new finding.
/// </summary>
public sealed record FindingChange(
    string RuleId,
    string Title,
    string Evidence,
    FindingChangeKind Kind,
    int Count);

public sealed record ComparedFile(
    string FilePath,
    ComparedFileStatus Status,
    string Explanation,
    ImmutableArray<FindingChange> FindingChanges,
    int? BaselineFindingCount,
    int? CurrentFindingCount,
    int? BaselineDiagnosticCount,
    int? CurrentDiagnosticCount);

public sealed record BatchReportComparison(
    ImmutableArray<ComparedFile> Files,
    ImmutableArray<string> Limitations)
{
    public int ComparedFileCount => Files.Count(file =>
        file.Status == ComparedFileStatus.Compared);

    public int IndeterminateFileCount => Files.Count(file =>
        file.Status == ComparedFileStatus.Indeterminate);

    public int OnlyInBaselineCount => Files.Count(file =>
        file.Status == ComparedFileStatus.OnlyInBaseline);

    public int OnlyInCurrentCount => Files.Count(file =>
        file.Status == ComparedFileStatus.OnlyInCurrent);

    public int NewlyDetectedCount => Count(FindingChangeKind.NewlyDetected);
    public int StillDetectedCount => Count(FindingChangeKind.StillDetected);
    public int NoLongerDetectedCount => Count(FindingChangeKind.NoLongerDetected);

    private int Count(FindingChangeKind kind) => Files.Sum(file =>
        file.FindingChanges.Where(change => change.Kind == kind)
            .Sum(change => change.Count));
}

/// <summary>
/// Compares two v0.5 batch JSON report snapshots, without re-inspecting source.
/// This first v0.6 slice is intentionally independent of the CLI and WinUI layer.
/// </summary>
public sealed class BatchReportComparisonService
{
    public const int MaximumReportCharacters = 32 * 1024 * 1024;

    private static readonly ImmutableArray<string> ComparisonLimitations =
        ImmutableArray.Create(
            "Findings are pattern matches, not proof that source executed or had an effect.",
            "No longer detected does not establish that a script or system is safe.",
            "A comparison uses rule ID and exact source evidence, not line numbers.",
            "Evidence edits, even cosmetic edits, may appear as a removed and a new match.",
            "File identity uses the full path recorded in each report; moves and renames are not tracked.",
            "Files with missing, invalid, or incompatible analysis cannot yield reliable finding deltas.",
            "Only existing JSON snapshots are compared; PowerShell source is never executed or read."
        );

    public BatchReportComparison Compare(string baselineJson, string currentJson)
    {
        Snapshot baseline = ReadSnapshot(baselineJson, nameof(baselineJson));
        Snapshot current = ReadSnapshot(currentJson, nameof(currentJson));

        var files = ImmutableArray.CreateBuilder<ComparedFile>();
        var accountedFor = new HashSet<string>(StringComparer.Ordinal);

        foreach (SnapshotFile oldFile in baseline.Files)
        {
            string key = NormalizeIdentity(oldFile.FilePath);
            accountedFor.Add(key);

            if (!current.ByIdentity.TryGetValue(key, out SnapshotFile? newFile))
            {
                files.Add(Unpaired(oldFile, ComparedFileStatus.OnlyInBaseline,
                    "This path is present only in the baseline report. This does not prove the file was deleted.",
                    isBaseline: true));
                continue;
            }

            files.Add(CompareFile(oldFile, newFile));
        }

        foreach (SnapshotFile newFile in current.Files)
        {
            if (!accountedFor.Add(NormalizeIdentity(newFile.FilePath)))
            {
                continue;
            }

            files.Add(Unpaired(newFile, ComparedFileStatus.OnlyInCurrent,
                "This path is present only in the current report. This does not prove the file was created.",
                isBaseline: false));
        }

        return new BatchReportComparison(files.ToImmutable(), ComparisonLimitations);
    }

    private static ComparedFile Unpaired(
        SnapshotFile file, ComparedFileStatus status, string explanation, bool isBaseline) =>
        new(file.FilePath, status, explanation,
            ImmutableArray<FindingChange>.Empty,
            isBaseline ? file.FindingCount : null,
            isBaseline ? null : file.FindingCount,
            isBaseline ? file.DiagnosticCount : null,
            isBaseline ? null : file.DiagnosticCount);

    private static ComparedFile CompareFile(SnapshotFile baseline, SnapshotFile current)
    {
        if (baseline.Outcome != "Parsed" || current.Outcome != "Parsed")
        {
            return Indeterminate(baseline, current,
                "One or both reports have an input or parser error; finding changes cannot be established.");
        }

        if (!string.Equals(baseline.RuleSetVersion, current.RuleSetVersion,
                StringComparison.Ordinal) ||
            !string.Equals(baseline.EngineVersion, current.EngineVersion,
                StringComparison.Ordinal))
        {
            return Indeterminate(baseline, current,
                "Engine or rule-set versions differ; changes could be due to detector behavior.");
        }

        var previous = baseline.Findings
            .GroupBy(finding => (finding.RuleId, finding.Evidence))
            .ToDictionary(group => group.Key, group => group.ToArray());
        var latest = current.Findings
            .GroupBy(finding => (finding.RuleId, finding.Evidence))
            .ToDictionary(group => group.Key, group => group.ToArray());

        var changes = ImmutableArray.CreateBuilder<FindingChange>();
        var signatures = previous.Keys.Concat(latest.Keys).Distinct()
            .OrderBy(key => key.RuleId, StringComparer.Ordinal)
            .ThenBy(key => key.Evidence, StringComparer.Ordinal);

        foreach (var signature in signatures)
        {
            previous.TryGetValue(signature, out ReportFinding[]? oldMatches);
            latest.TryGetValue(signature, out ReportFinding[]? newMatches);

            int oldCount = oldMatches?.Length ?? 0;
            int newCount = newMatches?.Length ?? 0;
            int shared = Math.Min(oldCount, newCount);
            string title = newMatches?.FirstOrDefault()?.Title ??
                oldMatches?.FirstOrDefault()?.Title ?? signature.RuleId;

            if (shared > 0)
            {
                changes.Add(new FindingChange(signature.RuleId, title,
                    signature.Evidence, FindingChangeKind.StillDetected, shared));
            }
            if (newCount > shared)
            {
                changes.Add(new FindingChange(signature.RuleId, title,
                    signature.Evidence, FindingChangeKind.NewlyDetected, newCount - shared));
            }
            if (oldCount > shared)
            {
                changes.Add(new FindingChange(signature.RuleId, title,
                    signature.Evidence, FindingChangeKind.NoLongerDetected, oldCount - shared));
            }
        }

        return new ComparedFile(current.FilePath, ComparedFileStatus.Compared,
            "Both snapshots were fully parsed with matching engine and rule-set versions.",
            changes.ToImmutable(), baseline.FindingCount, current.FindingCount,
            baseline.DiagnosticCount, current.DiagnosticCount);
    }

    private static ComparedFile Indeterminate(
        SnapshotFile baseline, SnapshotFile current, string reason) =>
        new(current.FilePath, ComparedFileStatus.Indeterminate, reason,
            ImmutableArray<FindingChange>.Empty,
            baseline.FindingCount, current.FindingCount,
            baseline.DiagnosticCount, current.DiagnosticCount);

    private static Snapshot ReadSnapshot(string json, string argument)
    {
        ArgumentNullException.ThrowIfNull(json);
        if (json.Length > MaximumReportCharacters)
        {
            throw new ArgumentException("Report exceeds the comparison size limit.", argument);
        }

        try
        {
            using JsonDocument document = JsonDocument.Parse(json,
                new JsonDocumentOptions { MaxDepth = 32 });
            JsonElement root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object ||
                Text(root, "reportType") != "batch" ||
                Text(root, "schemaVersion") != "0.1.0" ||
                Flag(root, "sourceExecuted"))
            {
                throw new FormatException(
                    "Expected an unexecuted batch report with schema version 0.1.0.");
            }

            JsonElement entries = Property(root, "files", JsonValueKind.Array);
            if (entries.GetArrayLength() != Number(root, "fileCount") ||
                entries.GetArrayLength() > BatchAnalysisService.MaximumFileCount)
            {
                throw new FormatException("Invalid report file count.");
            }

            var files = ImmutableArray.CreateBuilder<SnapshotFile>();
            var byIdentity = new Dictionary<string, SnapshotFile>(StringComparer.Ordinal);

            int entryIndex = 0;
            foreach (JsonElement entry in entries.EnumerateArray())
            {
                entryIndex++;
                string path = OptionalText(entry, "fullPath") ??
                    Text(entry, "requestedPath");
                string outcome = Text(entry, "outcome");
                if (outcome is not ("Parsed" or "ParsedWithErrors" or "InputError"))
                {
                    throw new FormatException("Unsupported file analysis outcome.");
                }
                if (string.IsNullOrWhiteSpace(path))
                {
                    if (outcome != "InputError")
                    {
                        throw new FormatException("Each analyzed file must have a path.");
                    }
                    // Empty requested paths are valid input errors in v0.5 reports.
                    // Keep them indeterminate, rather than rejecting the entire report.
                    path = $"(unidentified input #{entryIndex})";
                }

                string? ruleSet = null;
                string? engine = null;
                int? findingCount = null;
                int? diagnosticCount = null;
                var findings = ImmutableArray.CreateBuilder<ReportFinding>();

                if (outcome != "InputError")
                {
                    JsonElement analysis = Property(entry, "analysis", JsonValueKind.Object);
                    ruleSet = Text(analysis, "ruleSetVersion");
                    engine = Text(analysis, "engineVersion");
                    bool skipped = Flag(analysis, "rulesSkipped");
                    if (Flag(analysis, "sourceExecuted") ||
                        Text(analysis, "status") != outcome ||
                        skipped != (outcome == "ParsedWithErrors"))
                    {
                        throw new FormatException("Inconsistent nested analysis result.");
                    }

                    JsonElement items = Property(analysis, "findings", JsonValueKind.Array);
                    findingCount = Number(analysis, "findingCount");
                    diagnosticCount = Number(analysis, "diagnosticCount");
                    if (findingCount != items.GetArrayLength() ||
                        diagnosticCount != Property(analysis, "diagnostics", JsonValueKind.Array)
                            .GetArrayLength() ||
                        (skipped && findingCount != 0))
                    {
                        throw new FormatException("Inconsistent finding or diagnostic counts.");
                    }

                    foreach (JsonElement item in items.EnumerateArray())
                    {
                        findings.Add(new ReportFinding(
                            Text(item, "ruleId"), Text(item, "title"),
                            Text(item, "evidence")));
                    }
                }
                else if (Property(entry, "analysis").ValueKind != JsonValueKind.Null)
                {
                    throw new FormatException("Input errors cannot contain analysis results.");
                }

                var file = new SnapshotFile(path, outcome, ruleSet, engine,
                    findingCount, diagnosticCount, findings.ToImmutable());

                string identity = NormalizeIdentity(path);
                if (byIdentity.ContainsKey(identity))
                {
                    // A legitimate batch can contain one successful input and a
                    // second DuplicateInput error for the same canonical path.
                    if (outcome == "InputError" &&
                        Text(Property(entry, "inputError", JsonValueKind.Object), "code")
                            == "DuplicateInput")
                    {
                        continue;
                    }
                    throw new FormatException("Duplicate file identities in a report.");
                }

                byIdentity.Add(identity, file);
                files.Add(file);
            }

            return new Snapshot(files.ToImmutable(), byIdentity);
        }
        catch (Exception exception) when (exception is JsonException or FormatException
            or InvalidOperationException or KeyNotFoundException)
        {
            throw new ArgumentException(
                $"Invalid batch comparison input: {exception.Message}", argument, exception);
        }
    }

    private static JsonElement Property(JsonElement parent, string name,
        JsonValueKind? expected = null)
    {
        if (parent.ValueKind != JsonValueKind.Object ||
            !parent.TryGetProperty(name, out JsonElement value) ||
            (expected is not null && value.ValueKind != expected.Value))
        {
            throw new FormatException($"Missing or invalid property: {name}.");
        }
        return value;
    }

    private static string Text(JsonElement parent, string name)
    {
        JsonElement property = Property(parent, name, JsonValueKind.String);
        return property.GetString()!;
    }

    private static string? OptionalText(JsonElement parent, string name)
    {
        JsonElement property = Property(parent, name);
        return property.ValueKind switch
        {
            JsonValueKind.Null => null,
            JsonValueKind.String => property.GetString(),
            _ => throw new FormatException($"Invalid property: {name}.")
        };
    }

    private static int Number(JsonElement parent, string name)
    {
        JsonElement property = Property(parent, name, JsonValueKind.Number);
        if (!property.TryGetInt32(out int value) || value < 0)
        {
            throw new FormatException($"Invalid numeric property: {name}.");
        }
        return value;
    }

    private static bool Flag(JsonElement parent, string name)
    {
        JsonValueKind kind = Property(parent, name).ValueKind;
        return kind switch
        {
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            _ => throw new FormatException($"Invalid Boolean property: {name}.")
        };
    }

    private static string NormalizeIdentity(string path)
    {
        // Interpret Windows report paths the same way on Windows and CI hosts.
        // Posix paths remain case-sensitive. No file or directory access occurs.
        bool windows = (path.Length >= 3 && char.IsLetter(path[0]) &&
            path[1] == ':' && (path[2] == '\\' || path[2] == '/')) ||
            path.StartsWith("\\\\", StringComparison.Ordinal);
        return windows
            ? "win:" + path.Replace('/', '\\').ToUpperInvariant()
            : "other:" + path;
    }

    private sealed record ReportFinding(string RuleId, string Title, string Evidence);

    private sealed record SnapshotFile(
        string FilePath, string Outcome, string? RuleSetVersion,
        string? EngineVersion, int? FindingCount, int? DiagnosticCount,
        ImmutableArray<ReportFinding> Findings);

    private sealed record Snapshot(
        ImmutableArray<SnapshotFile> Files,
        Dictionary<string, SnapshotFile> ByIdentity);
}
