using System.Text;
using System.Text.Json;

namespace BombSquad.Analysis;

/// <summary>
/// A batch envelope containing unchanged single-file JSON reports. This does
/// not replace or change the existing single-file JSON schema.
/// </summary>
public static class BatchJsonAnalysisReportWriter
{
    public static string Serialize(BatchAnalysisResult batch)
    {
        ArgumentNullException.ThrowIfNull(batch);

        var report = new
        {
            schemaVersion = "0.1.0",
            reportType = "batch",
            fileCount = batch.FileCount,
            analyzedFileCount = batch.AnalyzedFileCount,
            inputErrorCount = batch.InputErrorCount,
            parserErrorFileCount = batch.ParserErrorFileCount,
            totalCommandCount = batch.TotalCommandCount,
            totalFindingCount = batch.TotalFindingCount,
            totalDiagnosticCount = batch.TotalDiagnosticCount,
            allFilesAnalyzed = batch.AllFilesAnalyzed,
            files = batch.Files.Select(file => new
            {
                requestedPath = file.RequestedPath,
                fullPath = file.FullPath,
                outcome = file.HasInputError
                    ? "InputError"
                    : file.HasParserErrors
                        ? "ParsedWithErrors"
                        : "Parsed",
                inputError = file.InputError,
                analysis = GetSingleFileReport(file)
            }).ToArray(),
            limitations = new[]
            {
                "Each file was inspected as text; supplied PowerShell was never executed.",
                "Parser errors skip detection rules for the affected file.",
                "The implemented detection rule set is partial. No findings does not establish safety.",
                "This report may contain source excerpts and local file paths."
            },
            sourceExecuted = false
        };

        return JsonSerializer.Serialize(report, new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            WriteIndented = true
        });
    }

    private static JsonElement? GetSingleFileReport(BatchFileAnalysis file)
    {
        if (file.Result is null)
        {
            return null;
        }

        // Preserve the exact existing single-file report format in each entry.
        using JsonDocument document = JsonDocument.Parse(
            JsonAnalysisReportWriter.Serialize(
                file.FullPath ?? file.RequestedPath, file.Result));

        return document.RootElement.Clone();
    }

    /// <summary>Writes a UTF-8 JSON report without overwriting existing files.</summary>
    public static string WriteNew(string reportPath, BatchAnalysisResult batch)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(reportPath);
        ArgumentNullException.ThrowIfNull(batch);

        string fullPath = Path.GetFullPath(reportPath);
        if (!string.Equals(Path.GetExtension(fullPath), ".json",
            StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("Report path must have a .json extension.");
        }

        string json = Serialize(batch);
        using var stream = new FileStream(
            fullPath, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        using var writer = new StreamWriter(stream, new UTF8Encoding(false));
        writer.WriteLine(json);
        return fullPath;
    }
}
