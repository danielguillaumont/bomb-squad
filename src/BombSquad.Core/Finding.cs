using System.Collections.Immutable;

namespace BombSquad.Core;

public sealed record Finding(
    string Id,
    string RuleId,
    string Title,
    FindingFamily Family,
    ReviewLevel ReviewLevel,
    Certainty Certainty,
    SourceSpan SourceSpan,
    string Evidence,
    string PotentialEffect,
    ImmutableArray<string> Limitations,
    string NextStep
);
