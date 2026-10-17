namespace BombSquad.Core;

public sealed record ParseDiagnostic(
    string Code,
    string Message,
    SourceSpan SourceSpan
);
