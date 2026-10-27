using System.Text;
using BombSquad.Analysis;

/// <summary>
/// Compares two previously exported BOMB SQUAD batch JSON reports.
/// Report paths are read-only inputs. Original PowerShell files are neither
/// opened nor executed. No PowerShell process is ever started.
/// </summary>
internal static class ComparisonCliCommand
{
    private const string Usage =
        "Usage: BombSquad.Cli --compare <baseline-batch.json> <current-batch.json> " +
        "[--json <new-comparison.json>] [--fail-on-new]";

    // UTF-8 uses at most four bytes per Unicode code point; allow BOM overhead.
    // The comparison engine separately limits the decoded character count.
    private const long MaximumInputBytes =
        (long)BatchReportComparisonService.MaximumReportCharacters * 4 + 4;

    public static int Run(string[] arguments)
    {
        if (arguments.Length < 3 || arguments[0] != "--compare")
        {
            return UsageError();
        }

        string baselinePath = arguments[1];
        string currentPath = arguments[2];
        string? outputPath = null;
        int index = 3;

        // Match the existing --batch command's deterministic option grammar.
        if (index < arguments.Length && arguments[index] == "--json")
        {
            if (index + 1 >= arguments.Length ||
                arguments[index + 1].StartsWith("--", StringComparison.Ordinal))
            {
                return UsageError();
            }

            outputPath = arguments[index + 1];
            index += 2;
        }

        bool failOnNew = false;
        if (index < arguments.Length && arguments[index] == "--fail-on-new")
        {
            failOnNew = true;
            index++;
        }

        if (index != arguments.Length)
        {
            return UsageError();
        }

        BatchReportComparison comparison;
        try
        {
            string baselineJson = ReadReport(baselinePath);
            string currentJson = ReadReport(currentPath);
            comparison = new BatchReportComparisonService().Compare(
                baselineJson, currentJson);
        }
        catch (Exception exception) when (IsExpectedInputException(exception))
        {
            Console.Error.WriteLine($"Comparison input error: {SafeLine(exception.Message)}");
            return 2;
        }

        Console.WriteLine("BOMB SQUAD");
        Console.WriteLine("Analysis: Baseline report comparison");
        Console.WriteLine("Scope: two previously generated batch JSON reports");
        Console.WriteLine("Original PowerShell source was not opened or executed.");
        Console.WriteLine();
        Console.WriteLine($"Baseline report: {SafeLine(Path.GetFullPath(baselinePath))}");
        Console.WriteLine($"Current report: {SafeLine(Path.GetFullPath(currentPath))}");
        Console.WriteLine();
        Console.WriteLine($"File identities: {comparison.Files.Length}");
        Console.WriteLine($"Compared files: {comparison.ComparedFileCount}");
        Console.WriteLine($"Indeterminate files: {comparison.IndeterminateFileCount}");
        Console.WriteLine($"Only in baseline: {comparison.OnlyInBaselineCount}");
        Console.WriteLine($"Only in current: {comparison.OnlyInCurrentCount}");
        Console.WriteLine($"Newly detected: {comparison.NewlyDetectedCount}");
        Console.WriteLine($"Still detected: {comparison.StillDetectedCount}");
        Console.WriteLine($"No longer detected: {comparison.NoLongerDetectedCount}");
        Console.WriteLine();

        foreach (ComparedFile file in comparison.Files)
        {
            Console.WriteLine($"[{file.Status}] {SafeLine(file.FilePath)}");
            if (file.Status != ComparedFileStatus.Compared)
            {
                Console.WriteLine($"  {SafeLine(file.Explanation)}");
                continue;
            }

            foreach (FindingChange change in file.FindingChanges)
            {
                Console.WriteLine(
                    $"  {change.Kind} x{change.Count}: " +
                    $"[{SafeLine(change.RuleId)}] {SafeLine(change.Title)}");
            }
            // The JSON report preserves evidence, but CLI console output does
            // not echo original source excerpts into CI or terminal logs.
        }

        if (outputPath is not null)
        {
            try
            {
                string saved = BatchReportComparisonJsonWriter.WriteNew(
                    outputPath, comparison);
                Console.WriteLine();
                Console.WriteLine($"Comparison JSON report: {SafeLine(saved)}");
                Console.WriteLine("Report may contain source evidence and local file paths.");
            }
            catch (Exception exception) when (IsExpectedInputException(exception))
            {
                Console.Error.WriteLine($"Report error: {SafeLine(exception.Message)}");
                return 2;
            }
        }

        Console.WriteLine();
        Console.WriteLine("No longer detected does not mean safe.");
        Console.WriteLine("Findings are static pattern matches, not proof of execution.");

        bool incomplete = comparison.IndeterminateFileCount > 0 ||
            comparison.OnlyInBaselineCount > 0 ||
            comparison.OnlyInCurrentCount > 0;

        if (incomplete)
        {
            Console.WriteLine(
                "Comparison incomplete for one or more file identities; " +
                "unpaired paths cannot establish new or resolved findings.");
        }

        if (failOnNew && incomplete)
        {
            Console.Error.WriteLine(
                "Comparison incomplete: strict mode requires all files to be " +
                "paired, parsed, and compatible.");
            return 3;
        }
        if (failOnNew && comparison.NewlyDetectedCount > 0)
        {
            Console.Error.WriteLine(
                $"Review required: {comparison.NewlyDetectedCount} newly detected finding(s).");
            return 1;
        }

        return 0;
    }

    private static string ReadReport(string requestedPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(requestedPath);
        string fullPath = Path.GetFullPath(requestedPath);
        if (!string.Equals(Path.GetExtension(fullPath), ".json",
                StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("Comparison inputs must be .json batch reports.");
        }

        var file = new FileInfo(fullPath);
        if (!file.Exists)
        {
            throw new FileNotFoundException("Comparison report not found.", fullPath);
        }
        if (file.Length > MaximumInputBytes)
        {
            throw new ArgumentException("Comparison report exceeds the size limit.");
        }

        using var reader = new StreamReader(
            fullPath, new UTF8Encoding(false, true),
            detectEncodingFromByteOrderMarks: true);
        string text = reader.ReadToEnd();
        if (text.Length > BatchReportComparisonService.MaximumReportCharacters)
        {
            throw new ArgumentException("Comparison report exceeds the character limit.");
        }
        return text;
    }

    private static bool IsExpectedInputException(Exception exception) =>
        exception is IOException or UnauthorizedAccessException or
            ArgumentException or NotSupportedException;

    private static string SafeLine(string text) => text
        .Replace("\r", "\\r", StringComparison.Ordinal)
        .Replace("\n", "\\n", StringComparison.Ordinal)
        .Replace("\t", "\\t", StringComparison.Ordinal);

    private static int UsageError()
    {
        Console.Error.WriteLine(Usage);
        return 2;
    }
}
