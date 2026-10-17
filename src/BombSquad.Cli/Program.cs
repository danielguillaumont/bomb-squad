using BombSquad.Analysis;
using BombSquad.Core;

Console.WriteLine("BOMB SQUAD");
Console.WriteLine("PowerShell Change & Risk Inspector");
Console.WriteLine();

var service = new AnalysisService();

var request = new AnalysisRequest(string.Empty);

AnalysisResult result = service.Analyze(request);

Console.WriteLine($"Engine version: {result.EngineVersion}");
Console.WriteLine($"Analysis status: {result.Status}");
Console.WriteLine($"Rules skipped: {result.RulesSkipped}");
Console.WriteLine($"Findings: {result.Findings.Length}");
Console.WriteLine();

Console.WriteLine("Limitations:");

foreach (string limitation in result.Limitations)
{
    Console.WriteLine($"- {limitation}");
}

Console.WriteLine();
Console.WriteLine("No PowerShell scripts were executed.");
