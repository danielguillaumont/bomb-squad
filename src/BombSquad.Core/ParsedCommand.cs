using System.Collections.Immutable;

namespace BombSquad.Core;

public sealed record ParsedCommand(
    string? CommandName,
    string Text,
    SourceSpan Span
)
{
    public ImmutableArray<ParsedLiteralParameter> LiteralParameters
        { get; init; } = ImmutableArray<ParsedLiteralParameter>.Empty;

    public bool IsDynamicInvocation { get; init; }
}
