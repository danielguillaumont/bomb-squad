using BombSquad.Analysis;
using BombSquad.Core;

/// <summary>
/// The CLI entry point for explicitly selected, read-only PowerShell batch analysis.
/// This class never starts a shell or evaluates user-supplied source.
/// </summary>
internal static class BatchCliCommand
{
    private const string Usage =
        "Usage: BombSquad.Cli --batch <file1.ps1> [file2.ps1 ...] " +
        "[--json <new-report.json>] [--fail-on-findings]";

    public static int Run(string[] arguments)
    {
        // Grammar: --batch input.ps1 [input.ps1 ...] [--json new.json]
        //          [--fail-on-findings]. Do not expand directories or wildcards.
        var paths = new List<string>();
        int index = 1;

        while (index < arguments.Length &&
               !arguments[index].StartsWith("--", StringComparison.Ordinal))
        {
            paths.Add(arguments[index]);
            index++;
        }

        string? reportPath = null;
        if (index < arguments.Length && arguments[index] == "--json")
        {
            if (index + 1 >= arguments.Length ||
                arguments[index + 1].StartsWith("--", StringComparison.Ordinal))
            {
                return UsageError();
            }

            reportPath = arguments[index + 1];
            index += 2;
        }

        bool failOnFindings = false;
        if (index < arguments.Length && arguments[index] == "--fail-on-findings")
        {
            failOnFindings = true;
            index++;
        }

        if (paths.Count == 0 ||
            paths.Count > BatchAnalysisService.MaximumFileCount ||
            index != arguments.Length)
        {
            return UsageError();
        }

        BatchAnalysisResult batch;
        try
        {
            batch = new BatchAnalysisService().AnalyzeFiles(paths);
        }
        catch (ArgumentException exception)
        {
            Console.Error.WriteLine($"Input error: {exception.Message}");
            return 2;
        }

        Console.WriteLine("BOMB SQUAD");
        Console.WriteLine("Analysis: PowerShell batch");
        Console.WriteLine("Scope: explicitly supplied .ps1 files only");
        Console.WriteLine();
        Console.WriteLine($"Files requested: {batch.FileCount}");
        Console.WriteLine($"Files analyzed: {batch.AnalyzedFileCount}");
        Console.WriteLine($"Input errors: {batch.InputErrorCount}");
        Console.WriteLine($"Files with parser errors: {batch.ParserErrorFileCount}");
        Console.WriteLine($"Commands found: {batch.TotalCommandCount}");
        Console.WriteLine($"Syntax diagnostics: {batch.TotalDiagnosticCount}");
        Console.WriteLine($"Findings: {batch.TotalFindingCount}");
        Console.WriteLine();

        for (int fileIndex = 0; fileIndex < batch.Files.Length; fileIndex++)
        {
            BatchFileAnalysis file = batch.Files[fileIndex];
            string outcome = file.HasInputError
                ? "InputError"
                : file.HasParserErrors
                    ? "ParsedWithErrors"
                    : "Parsed";

            Console.WriteLine($"[{fileIndex + 1}/{batch.FileCount}] {file.RequestedPath}");
            Console.WriteLine($"  Status: {outcome}");
            if (file.InputError is not null)
            {
                Console.WriteLine($"  Input error: {file.InputError.Code}: {file.InputError.Message}");
            }
            else if (file.Result is not null)
            {
                Console.WriteLine($"  Commands: {file.Result.Commands.Length}");
                Console.WriteLine($"  Diagnostics: {file.Result.Diagnostics.Length}");
                Console.WriteLine($"  Findings: {file.Result.Findings.Length}");
                Console.WriteLine($"  Rules skipped: {file.Result.RulesSkipped}");

                foreach (Finding finding in file.Result.Findings)
                {
                    Console.WriteLine(
                        $"  [{finding.RuleId}] Line {finding.SourceSpan.StartLine}, " +
                        $"Column {finding.SourceSpan.StartColumn}: {finding.Title}");
                }
            }
        }

        Console.WriteLine();
        if (batch.ParserErrorFileCount > 0)
        {
            Console.WriteLine(
                "Analysis incomplete: parser errors caused rules to be skipped " +
                "for affected files.");
        }
        if (batch.InputErrorCount > 0)
        {
            Console.WriteLine(
                "Analysis incomplete: one or more inputs could not be inspected.");
        }

        if (reportPath is not null)
        {
            try
            {
                string savedPath = BatchJsonAnalysisReportWriter.WriteNew(reportPath, batch);
                Console.WriteLine($"Batch JSON report: {savedPath}");
                Console.WriteLine("Report may contain original source excerpts and local paths.");
            }
            catch (Exception exception) when (
                exception is IOException or
                UnauthorizedAccessException or
                ArgumentException or
                NotSupportedException)
            {
                Console.Error.WriteLine($"Report error: {exception.Message}");
                return 2;
            }
        }

        Console.WriteLine("No findings does not establish safety.");
        Console.WriteLine("PowerShell source was analyzed as text, not executed.");

        if (batch.InputErrorCount > 0)
        {
            return 2;
        }
        if (failOnFindings && batch.ParserErrorFileCount > 0)
        {
            Console.Error.WriteLine(
                "Analysis incomplete: parser errors prevented full rule evaluation.");
            return 3;
        }
        if (failOnFindings && batch.TotalFindingCount > 0)
        {
            Console.Error.WriteLine(
                $"Review required: {batch.TotalFindingCount} potential operation(s) detected.");
            return 1;
        }

        return 0;
    }

    private static int UsageError()
    {
        Console.Error.WriteLine(Usage);
        return 2;
    }
}
