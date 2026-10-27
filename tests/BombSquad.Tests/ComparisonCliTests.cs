using System.Diagnostics;
using System.Text;
using System.Text.Json;
using BombSquad.Analysis;

namespace BombSquad.Tests;

public sealed class ComparisonCliTests
{
    [Fact]
    public void CompareMode_ReportsNewAndPersistentFindingsAndExportsJson()
    {
        using var folder = new ScratchDirectory();
        string script = folder.Write("same script.ps1",
            "Get-Date\nRemove-Item -LiteralPath 'demo-cache'");
        string baseline = folder.Snapshot("baseline.json", script);
        folder.Write("same script.ps1",
            "Get-Date\nRemove-Item -LiteralPath 'demo-cache'\nInvoke-Expression $dynamicSource");
        string current = folder.Snapshot("current.json", script);
        string output = Path.Combine(folder.Root, "comparison.json");

        CliResult result = RunCli("--compare", baseline, current, "--json", output);

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("Analysis: Baseline report comparison", result.Output);
        Assert.Contains("Compared files: 1", result.Output);
        Assert.Contains("Newly detected: 1", result.Output);
        Assert.Contains("Still detected: 1", result.Output);
        Assert.Contains("No longer detected: 0", result.Output);
        Assert.Contains("was not opened or executed", result.Output);
        Assert.True(File.Exists(output));

        using JsonDocument json = JsonDocument.Parse(File.ReadAllText(output));
        JsonElement root = json.RootElement;
        Assert.Equal("comparison", root.GetProperty("reportType").GetString());
        Assert.Equal(1, root.GetProperty("newlyDetectedCount").GetInt32());
        Assert.Equal(1, root.GetProperty("stillDetectedCount").GetInt32());
        Assert.False(root.GetProperty("sourceExecuted").GetBoolean());
    }

    [Fact]
    public void CompareMode_ReportsNoLongerDetectedWithoutClaimingSafety()
    {
        using var folder = new ScratchDirectory();
        string script = folder.Write("check.ps1", "Remove-Item 'demo-cache'");
        string baseline = folder.Snapshot("baseline.json", script);
        folder.Write("check.ps1", "Get-Date");
        string current = folder.Snapshot("current.json", script);

        CliResult result = RunCli("--compare", baseline, current);

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("Newly detected: 0", result.Output);
        Assert.Contains("No longer detected: 1", result.Output);
        Assert.Contains("No longer detected does not mean safe", result.Output);
    }

    [Fact]
    public void CompareMode_FailOnNewReturnsOneAfterSavingReport()
    {
        using var folder = new ScratchDirectory();
        string script = folder.Write("check.ps1", "Get-Date");
        string baseline = folder.Snapshot("baseline.json", script);
        folder.Write("check.ps1", "Invoke-Expression $dynamicSource");
        string current = folder.Snapshot("current.json", script);
        string output = Path.Combine(folder.Root, "comparison.json");

        CliResult result = RunCli("--compare", baseline, current,
            "--json", output, "--fail-on-new");

        Assert.Equal(1, result.ExitCode);
        Assert.True(File.Exists(output));
        Assert.Contains("Review required", result.Error);
    }

    [Fact]
    public void CompareMode_FailOnNewReturnsZeroWhenOnlyPersistentFindingsRemain()
    {
        using var folder = new ScratchDirectory();
        string script = folder.Write("check.ps1", "Remove-Item 'demo-cache'");
        string baseline = folder.Snapshot("baseline.json", script);
        string current = folder.Snapshot("current.json", script);

        CliResult result = RunCli("--compare", baseline, current, "--fail-on-new");

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("Newly detected: 0", result.Output);
        Assert.Contains("Still detected: 1", result.Output);
    }

    [Fact]
    public void CompareMode_FailOnNewReturnsThreeForParserErrors()
    {
        using var folder = new ScratchDirectory();
        string script = folder.Write("check.ps1", "Get-Date");
        string baseline = folder.Snapshot("baseline.json", script);
        folder.Write("check.ps1", "Write-Output 'unterminated");
        string current = folder.Snapshot("current.json", script);

        CliResult normal = RunCli("--compare", baseline, current);
        CliResult strict = RunCli("--compare", baseline, current, "--fail-on-new");

        Assert.Equal(0, normal.ExitCode);
        Assert.Contains("Indeterminate files: 1", normal.Output);
        Assert.Equal(3, strict.ExitCode);
        Assert.Contains("Comparison incomplete", strict.Error);
    }

    [Fact]
    public void CompareMode_FailOnNewReturnsThreeWhenCurrentHasAnUnpairedPath()
    {
        using var folder = new ScratchDirectory();
        string script = folder.Write("same.ps1", "Get-Date");
        string extra = folder.Write("new.ps1", "Invoke-Expression $dynamicSource");
        string baseline = folder.Snapshot("baseline.json", script);
        string current = folder.Snapshot("current.json", script, extra);

        CliResult result = RunCli("--compare", baseline, current, "--fail-on-new");

        Assert.Equal(3, result.ExitCode);
        Assert.Contains("Only in current: 1", result.Output);
        Assert.Contains("Comparison incomplete", result.Error);
    }

    [Fact]
    public void CompareMode_FailOnNewReturnsThreeWhenBaselineHasAnUnpairedPath()
    {
        using var folder = new ScratchDirectory();
        string script = folder.Write("same.ps1", "Get-Date");
        string extra = folder.Write("old.ps1", "Remove-Item 'cache'");
        string baseline = folder.Snapshot("baseline.json", script, extra);
        string current = folder.Snapshot("current.json", script);

        CliResult result = RunCli("--compare", baseline, current, "--fail-on-new");

        Assert.Equal(3, result.ExitCode);
        Assert.Contains("Only in baseline: 1", result.Output);
    }

    [Fact]
    public void CompareMode_DoesNotOpenOrExecuteOriginalPowerShellFiles()
    {
        using var folder = new ScratchDirectory();
        string marker = Path.Combine(folder.Root, "SHOULD-NOT-EXIST.txt");
        string script = folder.Write("source.ps1",
            "Set-Content -LiteralPath '" + marker.Replace("'", "''") + "' -Value 'executed'");
        string baseline = folder.Snapshot("baseline.json", script);
        string current = folder.Snapshot("current.json", script);
        File.Delete(script);

        CliResult result = RunCli("--compare", baseline, current);

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("Compared files: 1", result.Output);
        Assert.False(File.Exists(marker));
        Assert.False(File.Exists(script));
    }

    [Fact]
    public void CompareMode_DoesNotPrintSourceEvidenceToConsole()
    {
        using var folder = new ScratchDirectory();
        string script = folder.Write("check.ps1", "Get-Date");
        string baseline = folder.Snapshot("baseline.json", script);
        folder.Write("check.ps1", "Invoke-Expression 'PRIVATE_SOURCE_MARKER'");
        string current = folder.Snapshot("current.json", script);

        CliResult result = RunCli("--compare", baseline, current);

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("NewlyDetected", result.Output);
        Assert.DoesNotContain("PRIVATE_SOURCE_MARKER", result.Output);
    }

    [Fact]
    public void CompareMode_RejectsInvalidBatchJson()
    {
        using var folder = new ScratchDirectory();
        string invalid = folder.Write("not-a-batch.json", "{ not valid json");
        string script = folder.Write("check.ps1", "Get-Date");
        string current = folder.Snapshot("current.json", script);
        string output = Path.Combine(folder.Root, "should-not-exist.json");

        CliResult result = RunCli("--compare", invalid, current, "--json", output);

        Assert.Equal(2, result.ExitCode);
        Assert.Contains("Comparison input error", result.Error);
        Assert.False(File.Exists(output));
    }

    [Fact]
    public void CompareMode_RejectsReportOverwriteWithoutChangingContents()
    {
        using var folder = new ScratchDirectory();
        string script = folder.Write("check.ps1", "Get-Date");
        string baseline = folder.Snapshot("baseline.json", script);
        string current = folder.Snapshot("current.json", script);
        string output = folder.Write("existing.json", "KEEP ORIGINAL");

        CliResult result = RunCli("--compare", baseline, current, "--json", output);

        Assert.Equal(2, result.ExitCode);
        Assert.Contains("Report error", result.Error);
        Assert.Equal("KEEP ORIGINAL", File.ReadAllText(output));
    }

    [Fact]
    public void CompareMode_RejectsInvalidOptionsAndMissingInputs()
    {
        Assert.Equal(2, RunCli("--compare").ExitCode);
        Assert.Equal(2, RunCli("--compare", "old.json").ExitCode);
        Assert.Equal(2, RunCli("--compare", "old.json", "new.json", "--bad").ExitCode);
        Assert.Equal(2, RunCli("--compare", "old.json", "new.json", "--json").ExitCode);
        Assert.Equal(2, RunCli("--compare", "old.json", "new.json", "--fail-on-new", "--fail-on-new").ExitCode);
    }

    [Fact]
    public void CompareMode_RejectsNonJsonInputExtension()
    {
        using var folder = new ScratchDirectory();
        string script = folder.Write("check.ps1", "Get-Date");
        string current = folder.Snapshot("current.json", script);

        CliResult result = RunCli("--compare", script, current);

        Assert.Equal(2, result.ExitCode);
        Assert.Contains(".json", result.Error);
    }

    private static CliResult RunCli(params string[] arguments)
    {
        string root = FindRepositoryRoot();
        string configuration = new DirectoryInfo(AppContext.BaseDirectory).Parent!.Name;
        string assembly = Path.Combine(root, "src", "BombSquad.Cli", "bin",
            configuration, "net10.0", "BombSquad.Cli.dll");

        Assert.True(File.Exists(assembly),
            $"CLI assembly missing: {assembly}. Build the solution first.");

        var start = new ProcessStartInfo
        {
            FileName = Environment.GetEnvironmentVariable("DOTNET_HOST_PATH") ?? "dotnet",
            WorkingDirectory = root,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        start.ArgumentList.Add(assembly);
        foreach (string argument in arguments)
        {
            start.ArgumentList.Add(argument);
        }

        using var process = new Process { StartInfo = start };
        Assert.True(process.Start());
        Task<string> output = process.StandardOutput.ReadToEndAsync();
        Task<string> error = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit(20000))
        {
            process.Kill(entireProcessTree: true);
            throw new TimeoutException("Comparison CLI timed out.");
        }
        return new CliResult(process.ExitCode,
            output.GetAwaiter().GetResult(), error.GetAwaiter().GetResult());
    }

    private static string FindRepositoryRoot()
    {
        DirectoryInfo? directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null)
        {
            if (File.Exists(Path.Combine(directory.FullName, "BombSquad.slnx")))
            {
                return directory.FullName;
            }
            directory = directory.Parent;
        }
        throw new DirectoryNotFoundException("Could not find repository root.");
    }

    private sealed record CliResult(int ExitCode, string Output, string Error);

    private sealed class ScratchDirectory : IDisposable
    {
        public string Root { get; } = Path.Combine(
            Path.GetTempPath(), "bs-comparison-cli-" + Guid.NewGuid().ToString("N"));

        public ScratchDirectory() => Directory.CreateDirectory(Root);

        public string Write(string name, string content)
        {
            string path = Path.Combine(Root, name);
            File.WriteAllText(path, content, new UTF8Encoding(false));
            return path;
        }

        public string Snapshot(string fileName, params string[] scripts)
        {
            string path = Path.Combine(Root, fileName);
            BatchAnalysisResult batch = new BatchAnalysisService().AnalyzeFiles(scripts);
            return BatchJsonAnalysisReportWriter.WriteNew(path, batch);
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
