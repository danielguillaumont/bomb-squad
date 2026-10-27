using System.Text;
using System.Text.Json;

namespace BombSquad.Analysis;

/// <summary>
/// Serializes the result of comparing two existing batch JSON reports.
/// This component never reads or executes the original PowerShell scripts.
/// A report can include file paths and original source evidence.
/// </summary>
public static class BatchReportComparisonJsonWriter
{
    public static string Serialize(BatchReportComparison comparison)
    {
        ArgumentNullException.ThrowIfNull(comparison);

        var report = new
        {
            schemaVersion = "0.1.0",
            reportType = "comparison",
            comparisonBasis = "Two pre-existing BOMB SQUAD batch JSON reports",
            fileCount = comparison.Files.Length,
            comparedFileCount = comparison.ComparedFileCount,
            indeterminateFileCount = comparison.IndeterminateFileCount,
            onlyInBaselineCount = comparison.OnlyInBaselineCount,
            onlyInCurrentCount = comparison.OnlyInCurrentCount,
            newlyDetectedCount = comparison.NewlyDetectedCount,
            stillDetectedCount = comparison.StillDetectedCount,
            noLongerDetectedCount = comparison.NoLongerDetectedCount,
            files = comparison.Files.Select(file => new
            {
                filePath = file.FilePath,
                status = file.Status.ToString(),
                explanation = file.Explanation,
                baselineFindingCount = file.BaselineFindingCount,
                currentFindingCount = file.CurrentFindingCount,
                baselineDiagnosticCount = file.BaselineDiagnosticCount,
                currentDiagnosticCount = file.CurrentDiagnosticCount,
                findingChanges = file.FindingChanges.Select(change => new
                {
                    ruleId = change.RuleId,
                    title = change.Title,
                    evidence = change.Evidence,
                    kind = change.Kind.ToString(),
                    count = change.Count
                }).ToArray()
            }).ToArray(),
            limitations = comparison.Limitations.ToArray(),
            sourceExecuted = false
        };

        return JsonSerializer.Serialize(report, new JsonSerializerOptions
        {
            WriteIndented = true
        });
    }

    /// <summary>
    /// Saves a new UTF-8 JSON report. Existing files are never overwritten.
    /// </summary>
    public static string WriteNew(string reportPath, BatchReportComparison comparison)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(reportPath);
        ArgumentNullException.ThrowIfNull(comparison);

        string fullPath = Path.GetFullPath(reportPath);
        if (!string.Equals(Path.GetExtension(fullPath), ".json",
                StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("Comparison report path must end in .json.",
                nameof(reportPath));
        }

        string json = Serialize(comparison);
        using var stream = new FileStream(fullPath, FileMode.CreateNew,
            FileAccess.Write, FileShare.None);
        using var writer = new StreamWriter(stream, new UTF8Encoding(false));
        writer.WriteLine(json);
        return fullPath;
    }
}
