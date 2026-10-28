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

    // A parsed command inside a function definition is not proof of a function call.
    public bool IsInsideFunctionDefinition { get; init; }

    // A same-named function appears in this source. This is a conservative,
    // file-wide ambiguity indicator; it does not resolve PowerShell scopes.
    public bool MayBeShadowedBySourceFunction { get; init; }
}
