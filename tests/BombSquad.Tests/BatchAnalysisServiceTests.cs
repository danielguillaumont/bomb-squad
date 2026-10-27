using System.Text;
using BombSquad.Analysis;
using BombSquad.Core;

namespace BombSquad.Tests;

public sealed class BatchAnalysisServiceTests
{
    [Fact]
    public void AnalyzeFiles_ReportsFindingsIndependentlyInRequestedOrder()
    {
        using var folder = new TemporaryFolder();
        string clean = folder.Write("clean.ps1", "Get-Date");
        string changed = folder.Write("changed.ps1", "Remove-Item 'demo-cache'");

        BatchAnalysisResult batch = new BatchAnalysisService()
            .AnalyzeFiles(new[] { clean, changed });

        Assert.Equal(2, batch.FileCount);
        Assert.Equal(2, batch.AnalyzedFileCount);
        Assert.Equal(0, batch.InputErrorCount);
        Assert.True(batch.AllFilesAnalyzed);
        Assert.Equal(clean, batch.Files[0].FullPath);
        Assert.Equal(changed, batch.Files[1].FullPath);
        Assert.Empty(batch.Files[0].Result!.Findings);
        Assert.Equal("BS-FS-001", Assert.Single(batch.Files[1].Result!.Findings).RuleId);
        Assert.Equal(1, batch.TotalFindingCount);
        Assert.Equal(2, batch.TotalCommandCount);
    }

    [Fact]
    public void AnalyzeFiles_ParserFailureDoesNotSuppressOtherFiles()
    {
        using var folder = new TemporaryFolder();
        string malformed = folder.Write("malformed.ps1", "Write-Output 'unterminated");
        string valid = folder.Write("valid.ps1", "Invoke-Expression $source");

        BatchAnalysisResult batch = new BatchAnalysisService()
            .AnalyzeFiles(new[] { malformed, valid });

        Assert.Equal(2, batch.AnalyzedFileCount);
        Assert.Equal(1, batch.ParserErrorFileCount);
        Assert.False(batch.AllFilesAnalyzed);
        Assert.Equal(AnalysisStatus.ParsedWithErrors, batch.Files[0].Result!.Status);
        Assert.True(batch.Files[0].Result!.RulesSkipped);
        Assert.Empty(batch.Files[0].Result!.Findings);
        Assert.NotEmpty(batch.Files[0].Result!.Diagnostics);
        Assert.False(batch.Files[1].Result!.RulesSkipped);
        Assert.Equal("BS-DE-001", Assert.Single(batch.Files[1].Result!.Findings).RuleId);
    }

    [Fact]
    public void AnalyzeFiles_InvalidExtensionIsAnIsolatedInputError()
    {
        using var folder = new TemporaryFolder();
        string wrongExtension = folder.Write("not-powershell.txt", "Get-Date");
        string valid = folder.Write("valid.ps1", "Get-Date");

        BatchAnalysisResult batch = new BatchAnalysisService()
            .AnalyzeFiles(new[] { wrongExtension, valid });

        Assert.Equal("InvalidInput", batch.Files[0].InputError!.Code);
        Assert.Null(batch.Files[0].Result);
        Assert.NotNull(batch.Files[1].Result);
        Assert.Equal(1, batch.InputErrorCount);
        Assert.Equal(1, batch.AnalyzedFileCount);
        Assert.False(batch.AllFilesAnalyzed);
    }

    [Fact]
    public void AnalyzeFiles_MissingFileDoesNotStopOtherFiles()
    {
        using var folder = new TemporaryFolder();
        string missing = Path.Combine(folder.Root, "missing.ps1");
        string valid = folder.Write("real.ps1", "Remove-Item 'cache'");

        BatchAnalysisResult batch = new BatchAnalysisService()
            .AnalyzeFiles(new[] { missing, valid });

        Assert.Equal("FileNotFound", batch.Files[0].InputError!.Code);
        Assert.Null(batch.Files[0].Result);
        Assert.Single(batch.Files[1].Result!.Findings);
    }

    [Fact]
    public void AnalyzeFiles_RejectsOversizedFileWithoutReadingItAsPowerShell()
    {
        using var folder = new TemporaryFolder();
        string huge = Path.Combine(folder.Root, "huge.ps1");
        File.WriteAllBytes(
            huge, new byte[checked((int)PowerShellScriptFileReader.MaximumFileSizeBytes + 1)]);

        BatchAnalysisResult batch = new BatchAnalysisService()
            .AnalyzeFiles(new[] { huge });

        Assert.Equal(1, batch.InputErrorCount);
        Assert.Equal("FileReadError", batch.Files[0].InputError!.Code);
        Assert.Equal(0, batch.AnalyzedFileCount);
    }

    [Fact]
    public void AnalyzeFiles_RejectsInvalidUtf8ButKeepsOtherInputs()
    {
        using var folder = new TemporaryFolder();
        string invalid = Path.Combine(folder.Root, "invalid.ps1");
        File.WriteAllBytes(invalid, new byte[] { 0xC3, 0x28 });
        string valid = folder.Write("valid.ps1", "Get-Date");

        BatchAnalysisResult batch = new BatchAnalysisService()
            .AnalyzeFiles(new[] { invalid, valid });

        Assert.Equal("InvalidEncoding", batch.Files[0].InputError!.Code);
        Assert.Equal(1, batch.AnalyzedFileCount);
        Assert.NotNull(batch.Files[1].Result);
    }

    [Fact]
    public void AnalyzeFiles_DuplicateCanonicalPathIsNotInspectedTwice()
    {
        using var folder = new TemporaryFolder();
        string path = folder.Write("once.ps1", "Invoke-Expression $code");
        string alternate = Path.Combine(folder.Root, ".", "once.ps1");

        BatchAnalysisResult batch = new BatchAnalysisService()
            .AnalyzeFiles(new[] { path, alternate });

        Assert.Equal(1, batch.AnalyzedFileCount);
        Assert.Equal(1, batch.InputErrorCount);
        Assert.Equal("DuplicateInput", batch.Files[1].InputError!.Code);
        Assert.Null(batch.Files[1].Result);
        Assert.Equal(1, batch.TotalFindingCount);
    }

    [Fact]
    public void AnalyzeFiles_EmptyPathIsIsolatedFromValidInput()
    {
        using var folder = new TemporaryFolder();
        string valid = folder.Write("valid.ps1", "Get-Date");

        BatchAnalysisResult batch = new BatchAnalysisService()
            .AnalyzeFiles(new[] { "", valid });

        Assert.Equal("InvalidInput", batch.Files[0].InputError!.Code);
        Assert.NotNull(batch.Files[1].Result);
    }

    [Fact]
    public void AnalyzeFiles_EmptyOrNullBatchIsRejected()
    {
        var service = new BatchAnalysisService();
        Assert.Throws<ArgumentNullException>(() => service.AnalyzeFiles(null!));
        Assert.Throws<ArgumentException>(() => service.AnalyzeFiles(Array.Empty<string>()));
    }

    [Fact]
    public void AnalyzeFiles_MoreThanMaximumIsRejectedBeforeInspection()
    {
        var service = new BatchAnalysisService();
        string[] paths = Enumerable.Repeat("not-a-file.ps1",
            BatchAnalysisService.MaximumFileCount + 1).ToArray();

        Assert.Throws<ArgumentException>(() => service.AnalyzeFiles(paths));
    }

    [Fact]
    public void AnalyzeFiles_AcceptsExactlyMaximumFiles()
    {
        using var folder = new TemporaryFolder();
        string[] paths = Enumerable.Range(1, BatchAnalysisService.MaximumFileCount)
            .Select(i => folder.Write($"file-{i:D2}.ps1", "Get-Date"))
            .ToArray();

        BatchAnalysisResult batch = new BatchAnalysisService().AnalyzeFiles(paths);
        Assert.Equal(BatchAnalysisService.MaximumFileCount, batch.AnalyzedFileCount);
        Assert.True(batch.AllFilesAnalyzed);
    }

    [Fact]
    public void AnalyzeFiles_NeverExecutesAnySubmittedScript()
    {
        using var folder = new TemporaryFolder();
        string marker = Path.Combine(folder.Root, "execution-marker.txt");
        string script = folder.Write("untrusted.ps1",
            $"Set-Content -LiteralPath '{marker.Replace("'", "''")}' -Value 'executed'\n" +
            "Invoke-Expression $payload");

        BatchAnalysisResult batch = new BatchAnalysisService()
            .AnalyzeFiles(new[] { script });

        Assert.Equal(1, batch.AnalyzedFileCount);
        Assert.Equal(1, batch.TotalFindingCount);
        Assert.False(File.Exists(marker));
    }

    private sealed class TemporaryFolder : IDisposable
    {
        public string Root { get; } = Path.Combine(
            Path.GetTempPath(), "bs-batch-test-" + Guid.NewGuid().ToString("N"));

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
