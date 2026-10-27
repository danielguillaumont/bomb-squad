using System.Text;
using BombSquad.Analysis;
using BombSquad.Core;

if (args.Length > 0 && args[0] == "--batch")
{
    return BatchCliCommand.Run(args);
}

bool malformedDemo =
    args.Length == 1 && args[0] == "--demo-malformed";

bool jsonMode =
    args.Length >= 4 &&
    args[0] == "--file" &&
    args[2] == "--json" &&
    (args.Length == 4 ||
        (args.Length == 5 && args[4] == "--fail-on-findings"));

bool failOnFindings =
    args.Length >= 3 &&
    args[0] == "--file" &&
    args[^1] == "--fail-on-findings";

bool fileMode =
    args.Length >= 2 &&
    args[0] == "--file" &&
    (
        args.Length == 2 ||
        (args.Length == 3 && failOnFindings) ||
        jsonMode
    );

if (!(args.Length == 0 || malformedDemo || fileMode))
{
    Console.Error.WriteLine(
        "Usage: BombSquad.Cli [--demo-malformed | --file <path.ps1> [--json <report.json>] [--fail-on-findings]]"
    );

    return 2;
}

string source;
string sourceName;
string inputDescription;

if (fileMode)
{
    try
    {
        string fullPath = Path.GetFullPath(args[1]);

        if (!string.Equals(
            Path.GetExtension(fullPath),
            ".ps1",
            StringComparison.OrdinalIgnoreCase))
        {
            Console.Error.WriteLine(
                "Input error: only .ps1 files are supported."
            );

            return 2;
        }

        var file = new FileInfo(fullPath);

        if (!file.Exists)
        {
            Console.Error.WriteLine(
                $"Input error: file not found: {fullPath}"
            );

            return 2;
        }

        const long maxFileSize = 1024 * 1024;

        if (file.Length > maxFileSize)
        {
            Console.Error.WriteLine(
                "Input error: file exceeds the 1 MiB limit."
            );

            return 2;
        }

        using var reader = new StreamReader(
            fullPath,
            new UTF8Encoding(false, true),
            detectEncodingFromByteOrderMarks: true
        );

        source = reader.ReadToEnd();
        sourceName = fullPath;
        inputDescription = $"File: {fullPath}";
    }
    catch (Exception ex) when (
        ex is IOException or
        UnauthorizedAccessException or
        ArgumentException or
        NotSupportedException)
    {
        Console.Error.WriteLine($"Input error: {ex.Message}");

        return 2;
    }
}
else
{
    sourceName = "demo.ps1";
    inputDescription = "Built-in source text";

    source = malformedDemo
        ? "Write-Output 'unterminated"
        : "Get-Process\nRemove-Item -LiteralPath 'demo-cache'\nSet-MpPreference -DisableRealtimeMonitoring $true\nSet-ItemProperty -Path 'HKCU:\\Software\\BombSquadDemo' -Name Enabled -Value 1\nAdd-LocalGroupMember -Group 'Administrators' -Member 'demo-user'\nRegister-ScheduledTask -TaskName 'DemoTask' -Action $action\nInvoke-Expression $dynamicSource";
}
Console.WriteLine("BOMB SQUAD");
Console.WriteLine("PowerShell Change & Risk Inspector");
Console.WriteLine();

Console.WriteLine(
    fileMode
        ? "Analysis: PowerShell file"
        : malformedDemo
            ? "Demo: Malformed PowerShell"
            : "Demo: Six detection families"
);

Console.WriteLine(inputDescription);
Console.WriteLine();

var service = new AnalysisService();

AnalysisResult result = service.Analyze(
    new AnalysisRequest(source, sourceName)
);

if (jsonMode)
{
    try
    {
        string outputPath = JsonReportWriter.Write(
            args[3],
            sourceName,
            result
        );

        Console.WriteLine($"JSON report: {outputPath}");
        Console.WriteLine();
    }
    catch (Exception ex) when (
        ex is IOException or
        UnauthorizedAccessException or
        ArgumentException or
        NotSupportedException)
    {
        Console.Error.WriteLine($"Report error: {ex.Message}");
        return 2;
    }
}

Console.WriteLine($"Engine: {result.EngineVersion}");
Console.WriteLine($"Rule set: {result.RuleSetVersion}");
Console.WriteLine($"Status: {result.Status}");
Console.WriteLine($"Rules skipped: {result.RulesSkipped}");
Console.WriteLine();

Console.WriteLine($"Commands found: {result.Commands.Length}");

foreach (ParsedCommand command in result.Commands)
{
    string name = command.CommandName ?? "(dynamic/unresolved)";

    Console.WriteLine(
        $"- {name} | Line {command.Span.StartLine}, " +
        $"Column {command.Span.StartColumn}"
    );

    Console.WriteLine(
        $"  Source offsets: " +
        $"[{command.Span.StartOffset}, {command.Span.EndOffset})"
    );
}

Console.WriteLine();
Console.WriteLine($"Syntax diagnostics: {result.Diagnostics.Length}");

foreach (ParseDiagnostic diagnostic in result.Diagnostics)
{
    Console.WriteLine(
        $"- {diagnostic.Code} | " +
        $"Line {diagnostic.SourceSpan.StartLine}: " +
        diagnostic.Message
    );
}

Console.WriteLine();
Console.WriteLine($"Findings: {result.Findings.Length}");

foreach (Finding finding in result.Findings)
{
    Console.WriteLine();
    Console.WriteLine($"[{finding.RuleId}] {finding.Title}");
    Console.WriteLine($"Family: {finding.Family}");
    Console.WriteLine($"Review level: {finding.ReviewLevel}");
    Console.WriteLine($"Certainty: {finding.Certainty}");

    Console.WriteLine(
        $"Location: Line {finding.SourceSpan.StartLine}, " +
        $"Column {finding.SourceSpan.StartColumn}"
    );

    Console.WriteLine($"Evidence: {finding.Evidence}");
    Console.WriteLine($"Potential effect: {finding.PotentialEffect}");

    Console.WriteLine("Finding limitations:");

    foreach (string limitation in finding.Limitations)
    {
        Console.WriteLine($"- {limitation}");
    }

    Console.WriteLine($"Next step: {finding.NextStep}");
}

if (result.RulesSkipped)
{
    Console.WriteLine(
        "Detection rules were skipped; no rule findings were produced."
    );
}
else if (result.Findings.IsEmpty)
{
    Console.WriteLine(
        "No findings from the implemented rules. " +
        "This does not establish safety."
    );
}

if (!result.UnsupportedConstructs.IsEmpty)
{
    Console.WriteLine();
    Console.WriteLine("Unresolved constructs:");

    foreach (string item in result.UnsupportedConstructs)
    {
        Console.WriteLine($"- {item}");
    }
}

Console.WriteLine();
Console.WriteLine("Analysis limitations:");

foreach (string limitation in result.Limitations)
{
    Console.WriteLine($"- {limitation}");
}

Console.WriteLine();
Console.WriteLine(
    "PowerShell source was analyzed as text, not executed."
);

if (failOnFindings)
{
    if (result.RulesSkipped)
    {
        Console.Error.WriteLine(
            "Analysis incomplete: parser errors caused detection rules to be skipped."
        );

        return 3;
    }

    if (!result.Findings.IsEmpty)
    {
        Console.Error.WriteLine(
            $"Review required: {result.Findings.Length} potential operation(s) detected."
        );

        return 1;
    }
}

return 0;
