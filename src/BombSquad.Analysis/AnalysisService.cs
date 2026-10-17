using System.Collections.Immutable;
using BombSquad.Core;

namespace BombSquad.Analysis;

public sealed class AnalysisService
{
    public AnalysisResult Analyze(AnalysisRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(request.SourceText);

        return new AnalysisResult(
            Status: AnalysisStatus.NotImplemented,
            Findings: ImmutableArray<Finding>.Empty,
            Diagnostics: ImmutableArray<ParseDiagnostic>.Empty,
            UnsupportedConstructs: ImmutableArray<string>.Empty,
            Limitations: ImmutableArray.Create(
                "PowerShell source was not parsed.",
                "Detection rules have not been implemented.",
                "No safety verdict is available."
            ),
            EngineVersion: "0.0.0",
            RuleSetVersion: "none",
            RulesSkipped: true
        );
    }
}
