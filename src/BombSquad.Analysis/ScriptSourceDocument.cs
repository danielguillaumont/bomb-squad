using System.Collections.Immutable;

namespace BombSquad.Analysis;

/// <summary>A read-only, offset-preserving view of the original PowerShell text.</summary>
public sealed class ScriptSourceDocument
{
    public string SourceText { get; }
    public ImmutableArray<ScriptSourceLine> Lines { get; }

    public ScriptSourceDocument(string sourceText)
    {
        ArgumentNullException.ThrowIfNull(sourceText);
        SourceText = sourceText;

        var lines = ImmutableArray.CreateBuilder<ScriptSourceLine>();
        int start = 0;
        int number = 1;

        for (int index = 0; index < sourceText.Length; index++)
        {
            char character = sourceText[index];
            if (character is not ('\r' or '\n'))
            {
                continue;
            }

            lines.Add(new ScriptSourceLine(
                number++, sourceText[start..index], start, index));

            if (character == '\r' &&
                index + 1 < sourceText.Length &&
                sourceText[index + 1] == '\n')
            {
                index++;
            }

            start = index + 1;
        }

        // Retain the final empty line when the file ends in a newline.
        lines.Add(new ScriptSourceLine(
            number, sourceText[start..], start, sourceText.Length));

        Lines = lines.ToImmutable();
    }

    public ScriptSourceLine? GetLine(int oneBasedLineNumber)
    {
        return oneBasedLineNumber >= 1 && oneBasedLineNumber <= Lines.Length
            ? Lines[oneBasedLineNumber - 1]
            : null;
    }

    public ImmutableArray<ScriptSourceLine> GetContext(
        int oneBasedLineNumber,
        int radius = 3)
    {
        if (radius < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(radius));
        }

        if (GetLine(oneBasedLineNumber) is null)
        {
            return ImmutableArray<ScriptSourceLine>.Empty;
        }

        int first = (int)Math.Max(1L, (long)oneBasedLineNumber - radius);
        int last = (int)Math.Min(Lines.Length, (long)oneBasedLineNumber + radius);
        return Lines.Skip(first - 1).Take(last - first + 1).ToImmutableArray();
    }
}

public sealed record ScriptSourceLine(
    int LineNumber,
    string Text,
    int StartOffset,
    int EndOffset)
{
    public string LineNumberDisplay => LineNumber.ToString("D4");
}
