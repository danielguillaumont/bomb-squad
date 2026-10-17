using System.Collections.Immutable;
using BombSquad.Core;

namespace BombSquad.Analysis;

public sealed class AnalysisService
{
    private readonly PowerShellParser _parser = new();

    public AnalysisResult Analyze(AnalysisRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(request.SourceText);

        PowerShellParseResult parsed = _parser.Parse(
            request.SourceText
        );

        AnalysisStatus status = parsed.Diagnostics.IsEmpty
            ? AnalysisStatus.Parsed
            : AnalysisStatus.ParsedWithErrors;

        return new AnalysisResult(
            Status: status,
            Findings: ImmutableArray<Finding>.Empty,
            Diagnostics: parsed.Diagnostics,
            UnsupportedConstructs: ImmutableArray<string>.Empty,
            Limitations: ImmutableArray.Create(
                "Only PowerShell syntax was parsed; behavior was not evaluated.",
                "Detection rules have not been implemented.",
                "Unsupported and dynamic behavior has not yet been assessed.",
                "No safety verdict is available."
            ),
            EngineVersion: "0.1.0-dev",
            RuleSetVersion: "none",
            RulesSkipped: true
        )
        {
            Commands = parsed.Commands
        };
    }
}
