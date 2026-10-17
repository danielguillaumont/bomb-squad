using System.Text;
using System.Text.Json;
using BombSquad.Core;

namespace BombSquad.Analysis;

/// <summary>
/// Produces the same versioned static-analysis JSON for the CLI and Windows desktop.
/// It serializes analysis results and never evaluates supplied PowerShell source.
/// </summary>
public static class JsonAnalysisReportWriter
{
    public static string Serialize(string sourceFile, AnalysisResult result)
    {
        ArgumentNullException.ThrowIfNull(result);

        var report = new
        {
            schemaVersion = "0.1.0",
            sourceFile,
            engineVersion = result.EngineVersion,
            ruleSetVersion = result.RuleSetVersion,
            status = result.Status.ToString(),
            rulesSkipped = result.RulesSkipped,
            commandCount = result.Commands.Length,
            diagnosticCount = result.Diagnostics.Length,
            findingCount = result.Findings.Length,

            findings = result.Findings.Select(finding => new
            {
                id = finding.Id,
                ruleId = finding.RuleId,
                title = finding.Title,
                family = finding.Family.ToString(),
                reviewLevel = finding.ReviewLevel.ToString(),
                certainty = finding.Certainty.ToString(),
                sourceSpan = finding.SourceSpan,
                evidence = finding.Evidence,
                potentialEffect = finding.PotentialEffect,
                limitations = finding.Limitations.ToArray(),
                nextStep = finding.NextStep
            }).ToArray(),

            diagnostics = result.Diagnostics.Select(diagnostic => new
            {
                code = diagnostic.Code.ToString(),
                message = diagnostic.Message,
                sourceSpan = diagnostic.SourceSpan
            }).ToArray(),

            unresolvedConstructs =
                result.UnsupportedConstructs.ToArray(),

            limitations = result.Limitations.ToArray(),
            sourceExecuted = false
        };

        return JsonSerializer.Serialize(
            report,
            new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                WriteIndented = true
            }
        );
    }

    // FileMode.CreateNew protects CLI output from silent overwrites.
    // The desktop uses the native Save dialog, which confirms replacement.
    public static string WriteNew(string reportPath, string sourceFile, AnalysisResult result)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(reportPath);
        ArgumentNullException.ThrowIfNull(result);

        string fullPath = Path.GetFullPath(reportPath);
        if (!string.Equals(
            Path.GetExtension(fullPath),
            ".json",
            StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("Report path must have a .json extension.");
        }

        string json = Serialize(sourceFile, result);

        using var stream = new FileStream(
            fullPath,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.None
        );

        using var writer = new StreamWriter(stream, new UTF8Encoding(false));
        writer.WriteLine(json);
        return fullPath;
    }
}
