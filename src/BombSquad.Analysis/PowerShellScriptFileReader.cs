using System.Text;

namespace BombSquad.Analysis;

public sealed record PowerShellScriptFile(string FullPath, string SourceText);

public static class PowerShellScriptFileReader
{
    public const long MaximumFileSizeBytes = 1024 * 1024;

    public static PowerShellScriptFile Read(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        string fullPath = Path.GetFullPath(path);

        if (!string.Equals(
            Path.GetExtension(fullPath),
            ".ps1",
            StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException(
                "Only .ps1 PowerShell files are supported.",
                nameof(path));
        }

        if (!File.Exists(fullPath))
        {
            throw new FileNotFoundException(
                "The selected PowerShell file was not found.",
                fullPath);
        }

        using var stream = new FileStream(
            fullPath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read);

        if (stream.Length > MaximumFileSizeBytes)
        {
            throw new IOException(
                "The selected script exceeds the 1 MiB inspection limit.");
        }

        using var reader = new StreamReader(
            stream,
            new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true),
            detectEncodingFromByteOrderMarks: true);

        string source = reader.ReadToEnd();

        if (stream.Position > MaximumFileSizeBytes)
        {
            throw new IOException(
                "The selected script exceeds the 1 MiB inspection limit.");
        }

        return new PowerShellScriptFile(fullPath, source);
    }
}
