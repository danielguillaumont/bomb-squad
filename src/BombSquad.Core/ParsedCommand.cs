namespace BombSquad.Core;

public sealed record ParsedCommand(
    string? CommandName,
    string Text,
    SourceSpan Span
);
