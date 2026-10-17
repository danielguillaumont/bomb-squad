using System.Collections.Immutable;

namespace BombSquad.Core;

public sealed record AnalysisResult(
    AnalysisStatus Status,
    ImmutableArray<Finding> Findings,
    ImmutableArray<ParseDiagnostic> Diagnostics,
    ImmutableArray<string> UnsupportedConstructs,
    ImmutableArray<string> Limitations,
    string EngineVersion,
    string RuleSetVersion,
    bool RulesSkipped
);
