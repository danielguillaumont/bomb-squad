using System.Collections.Immutable;

namespace BombSquad.Core;

public sealed record PowerShellParseResult(
    ImmutableArray<ParsedCommand> Commands,
    ImmutableArray<ParseDiagnostic> Diagnostics
);
