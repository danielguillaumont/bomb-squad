using BombSquad.Analysis;
using BombSquad.Core;

if (args.Length > 1 ||
    (args.Length == 1 && args[0] != "--demo-malformed"))
{
    Console.Error.WriteLine(
        "Usage: BombSquad.Cli [--demo-malformed]"
    );

    return 2;
}

bool malformedDemo = args.Length == 1;

string source = malformedDemo
    ? "Write-Output 'unterminated"
    : "Get-Process\nRemove-Item -LiteralPath 'demo-cache'\nSet-MpPreference -DisableRealtimeMonitoring $true\nSet-ItemProperty -Path 'HKCU:\\Software\\BombSquadDemo' -Name Enabled -Value 1";

Console.WriteLine("BOMB SQUAD");
Console.WriteLine("PowerShell Change & Risk Inspector");
Console.WriteLine();

Console.WriteLine(
    malformedDemo
        ? "Demo: Malformed PowerShell"
        : "Demo: Filesystem, Defender and Registry changes"
);

Console.WriteLine("Input: Built-in source text");
Console.WriteLine();

var service = new AnalysisService();

AnalysisResult result = service.Analyze(
    new AnalysisRequest(source, "demo.ps1")
);

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

return 0;
