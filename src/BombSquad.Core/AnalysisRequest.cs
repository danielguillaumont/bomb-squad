namespace BombSquad.Core;

public sealed record AnalysisRequest(
    string SourceText,
    string? SourceName = null
);
