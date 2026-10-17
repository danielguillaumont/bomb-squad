namespace BombSquad.Core;

// Start offset is inclusive; end offset is exclusive.
public sealed record SourceSpan(
    int StartOffset,
    int EndOffset,
    int StartLine,
    int StartColumn,
    int EndLine,
    int EndColumn
)
{
    public int Length => EndOffset - StartOffset;
}
