using System.Text;

namespace BombSquad.Analysis;

/// <summary>
/// Validates a user-pasted PowerShell source snapshot without writing it to disk
/// or executing it. All offsets are preserved for AST-backed evidence navigation.
/// </summary>
public static class PastedPowerShellInput
{
    public const int MaximumSourceSizeBytes = (int)PowerShellScriptFileReader.MaximumFileSizeBytes;
    public const string SourceIdentifier = "pasted-snippet.ps1";

    private static readonly UTF8Encoding StrictUtf8 = new(
        encoderShouldEmitUTF8Identifier: false,
        throwOnInvalidBytes: true);

    public static string Validate(string? sourceText)
    {
        if (string.IsNullOrWhiteSpace(sourceText))
        {
            throw new ArgumentException(
                "Paste a PowerShell snippet before inspecting.", nameof(sourceText));
        }

        if (sourceText.Contains('\0'))
        {
            throw new ArgumentException(
                "Pasted source contains a NUL character and cannot be inspected.",
                nameof(sourceText));
        }

        // Count UTF-8 bytes rather than characters: non-ASCII input can use
        // substantially more memory, and file inspection has the same 1 MiB limit.
        if (StrictUtf8.GetByteCount(sourceText) > MaximumSourceSizeBytes)
        {
            throw new ArgumentException(
                "Pasted source exceeds the 1 MiB inspection limit.",
                nameof(sourceText));
        }

        return sourceText; // No trimming, normalization, file I/O or evaluation.
    }
}
