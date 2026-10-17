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
    : "Get-Process\nRemove-Item -LiteralPath 'demo-cache'";

Console.WriteLine("BOMB SQUAD");
Console.WriteLine("PowerShell Change & Risk Inspector");
Console.WriteLine();

Console.WriteLine(
    malformedDemo
        ? "Demo: Malformed PowerShell"
        : "Demo: Valid PowerShell"
);

Console.WriteLine("Input: Built-in source text");
Console.WriteLine();

var service = new AnalysisService();

AnalysisResult result = service.Analyze(
    new AnalysisRequest(source, "demo.ps1")
);

Console.WriteLine($"Engine: {result.EngineVersion}");
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
Console.WriteLine("Analysis limitations:");

foreach (string limitation in result.Limitations)
{
    Console.WriteLine($"- {limitation}");
}

Console.WriteLine();
Console.WriteLine("PowerShell source was not executed.");

return 0;
