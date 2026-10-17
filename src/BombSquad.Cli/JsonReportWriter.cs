using System.Text;
using System.Text.Json;
using BombSquad.Core;

internal static class JsonReportWriter
{
    public static string Write(
        string reportPath,
        string sourceFile,
        AnalysisResult result)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(reportPath);
        ArgumentNullException.ThrowIfNull(result);

        string fullPath = Path.GetFullPath(reportPath);

        if (!string.Equals(
            Path.GetExtension(fullPath),
            ".json",
            StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException(
                "Report path must have a .json extension."
            );
        }

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

        string json = JsonSerializer.Serialize(
            report,
            new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                WriteIndented = true
            }
        );

        using var stream = new FileStream(
            fullPath,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.None
        );

        using var writer = new StreamWriter(
            stream,
            new UTF8Encoding(false)
        );

        writer.WriteLine(json);

        return fullPath;
    }
}
