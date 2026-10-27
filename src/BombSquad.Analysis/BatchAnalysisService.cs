using System.Collections.Immutable;
using System.Text;
using BombSquad.Core;

namespace BombSquad.Analysis;

/// <summary>
/// Describes one explicitly supplied input. An input error is different from a
/// PowerShell parse error: parse errors retain an AnalysisResult with diagnostics.
/// </summary>
public sealed record BatchInputError(string Code, string Message);

public sealed record BatchFileAnalysis(
    string RequestedPath,
    string? FullPath,
    AnalysisResult? Result,
    BatchInputError? InputError)
{
    public bool HasInputError => InputError is not null;
    public bool HasParserErrors => Result?.RulesSkipped == true;
}

public sealed record BatchAnalysisResult(ImmutableArray<BatchFileAnalysis> Files)
{
    public int FileCount => Files.Length;
    public int AnalyzedFileCount => Files.Count(file => file.Result is not null);
    public int InputErrorCount => Files.Count(file => file.HasInputError);
    public int ParserErrorFileCount => Files.Count(file => file.HasParserErrors);
    public int TotalCommandCount => Files.Sum(file => file.Result?.Commands.Length ?? 0);
    public int TotalFindingCount => Files.Sum(file => file.Result?.Findings.Length ?? 0);
    public int TotalDiagnosticCount => Files.Sum(file => file.Result?.Diagnostics.Length ?? 0);

    // No safety verdict: this means all inputs were parsed and checked by the
    // existing partial rule set, not that those scripts are safe to execute.
    public bool AllFilesAnalyzed =>
        FileCount > 0 && InputErrorCount == 0 && ParserErrorFileCount == 0;
}

/// <summary>
/// Inspects up to 50 explicitly selected .ps1 files, sequentially and read-only.
/// Never enumerates directories or launches PowerShell processes.
/// </summary>
public sealed class BatchAnalysisService
{
    public const int MaximumFileCount = 50;

    private readonly AnalysisService _analysis = new();

    public BatchAnalysisResult AnalyzeFiles(IEnumerable<string> paths)
    {
        ArgumentNullException.ThrowIfNull(paths);

        // Materialize at most 51 items before starting any inspection, so an
        // oversized request cannot produce partial work or an unbounded list.
        string[] requested = paths.Take(MaximumFileCount + 1).ToArray();

        if (requested.Length == 0)
        {
            throw new ArgumentException(
                "Select at least one .ps1 file for inspection.", nameof(paths));
        }

        if (requested.Length > MaximumFileCount)
        {
            throw new ArgumentException(
                $"A batch can contain at most {MaximumFileCount} files.",
                nameof(paths));
        }

        var files = ImmutableArray.CreateBuilder<BatchFileAnalysis>();
        var seenPaths = new HashSet<string>(
            OperatingSystem.IsWindows()
                ? StringComparer.OrdinalIgnoreCase
                : StringComparer.Ordinal);

        foreach (string requestedPath in requested)
        {
            string? fullPath = null;

            try
            {
                if (string.IsNullOrWhiteSpace(requestedPath))
                {
                    throw new ArgumentException("The input path is empty.");
                }

                fullPath = Path.GetFullPath(requestedPath);

                if (!seenPaths.Add(fullPath))
                {
                    files.Add(new BatchFileAnalysis(
                        requestedPath, fullPath, null,
                        new BatchInputError(
                            "DuplicateInput",
                            "This file was already included in the batch.")));
                    continue;
                }

                // Reuse the existing extension, existence, size and strict
                // Unicode validation rather than introducing a second reader.
                PowerShellScriptFile file =
                    PowerShellScriptFileReader.Read(fullPath);

                AnalysisResult result = _analysis.Analyze(
                    new AnalysisRequest(file.SourceText, file.FullPath));

                files.Add(new BatchFileAnalysis(
                    requestedPath, file.FullPath, result, null));
            }
            catch (Exception ex) when (
                ex is IOException or
                UnauthorizedAccessException or
                ArgumentException or
                NotSupportedException)
            {
                files.Add(new BatchFileAnalysis(
                    requestedPath ?? string.Empty, fullPath, null,
                    new BatchInputError(GetErrorCode(ex), ex.Message)));
            }
        }

        return new BatchAnalysisResult(files.ToImmutable());
    }

    private static string GetErrorCode(Exception error) => error switch
    {
        FileNotFoundException => "FileNotFound",
        DirectoryNotFoundException => "DirectoryNotFound",
        UnauthorizedAccessException => "AccessDenied",
        DecoderFallbackException => "InvalidEncoding",
        IOException => "FileReadError",
        NotSupportedException => "UnsupportedInput",
        ArgumentException => "InvalidInput",
        _ => "InputError"
    };
}
