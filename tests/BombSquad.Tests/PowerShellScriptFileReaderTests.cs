using System.Text;
using BombSquad.Analysis;
using BombSquad.Core;

namespace BombSquad.Tests;

public sealed class PowerShellScriptFileReaderTests
{
    [Fact]
    public void Read_ValidPs1ReturnsOriginalTextAndFullPath()
    {
        using var folder = new TemporaryFolder();
        string path = folder.Write("test file.ps1", "Get-Date\nGet-Process");

        PowerShellScriptFile file = PowerShellScriptFileReader.Read(path);

        Assert.Equal(Path.GetFullPath(path), file.FullPath);
        Assert.Equal("Get-Date\nGet-Process", file.SourceText);
    }

    [Fact]
    public void Read_EmptyPs1ReturnsEmptySource()
    {
        using var folder = new TemporaryFolder();
        string path = folder.Write("empty.ps1", string.Empty);

        Assert.Equal(string.Empty, PowerShellScriptFileReader.Read(path).SourceText);
    }

    [Fact]
    public void Read_Utf16BomIsRecognized()
    {
        using var folder = new TemporaryFolder();
        string path = Path.Combine(folder.Root, "unicode.ps1");
        File.WriteAllText(path, "Write-Output 'hello'", Encoding.Unicode);

        Assert.Equal(
            "Write-Output 'hello'",
            PowerShellScriptFileReader.Read(path).SourceText);
    }

    [Fact]
    public void Read_InvalidUtf8IsRejected()
    {
        using var folder = new TemporaryFolder();
        string path = Path.Combine(folder.Root, "bad.ps1");
        File.WriteAllBytes(path, new byte[] { 0xC3, 0x28 });

        Assert.Throws<DecoderFallbackException>(
            () => PowerShellScriptFileReader.Read(path));
    }

    [Fact]
    public void Read_MissingFileIsRejected()
    {
        using var folder = new TemporaryFolder();
        string path = Path.Combine(folder.Root, "missing.ps1");

        Assert.Throws<FileNotFoundException>(
            () => PowerShellScriptFileReader.Read(path));
    }

    [Fact]
    public void Read_NonPs1ExtensionIsRejected()
    {
        using var folder = new TemporaryFolder();
        string path = folder.Write("text.txt", "Get-Date");

        Assert.Throws<ArgumentException>(
            () => PowerShellScriptFileReader.Read(path));
    }

    [Fact]
    public void Read_OversizedPs1IsRejected()
    {
        using var folder = new TemporaryFolder();
        string path = Path.Combine(folder.Root, "large.ps1");
        File.WriteAllBytes(
            path,
            new byte[checked((int)PowerShellScriptFileReader.MaximumFileSizeBytes + 1)]);

        Assert.Throws<IOException>(
            () => PowerShellScriptFileReader.Read(path));
    }

    [Fact]
    public void Read_UppercaseExtensionIsSupported()
    {
        using var folder = new TemporaryFolder();
        string path = folder.Write("SCRIPT.PS1", "Get-Date");

        Assert.Equal("Get-Date", PowerShellScriptFileReader.Read(path).SourceText);
    }

    [Fact]
    public void Read_AndAnalyzeNeverExecutesTheSource()
    {
        using var folder = new TemporaryFolder();
        string marker = Path.Combine(folder.Root, "should-not-exist.txt");
        string escaped = marker.Replace("'", "''");

        string path = folder.Write(
            "untrusted.ps1",
            $"Set-Content -LiteralPath '{escaped}' -Value 'executed'\n" +
            "Invoke-Expression $source");

        PowerShellScriptFile script = PowerShellScriptFileReader.Read(path);
        var result = new AnalysisService().Analyze(
            new AnalysisRequest(script.SourceText, script.FullPath));

        Assert.Contains(result.Findings, item => item.RuleId == "BS-DE-001");
        Assert.False(File.Exists(marker));
    }

    private sealed class TemporaryFolder : IDisposable
    {
        public string Root { get; } = Path.Combine(
            Path.GetTempPath(),
            "bomb-squad-file-reader-" + Guid.NewGuid().ToString("N"));

        public TemporaryFolder() => Directory.CreateDirectory(Root);

        public string Write(string name, string text)
        {
            string path = Path.Combine(Root, name);
            File.WriteAllText(path, text, new UTF8Encoding(false));
            return path;
        }

        public void Dispose()
        {
            if (Directory.Exists(Root))
            {
                Directory.Delete(Root, recursive: true);
            }
        }
    }
}
