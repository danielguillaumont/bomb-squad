using System.Diagnostics;
using System.Text;
using System.Text.Json;

namespace BombSquad.Tests;

public sealed class BatchCliTests
{
    [Fact]
    public void BatchMode_ReportsTwoFilesInOrderAndWritesJson()
    {
        using var folder = new ScratchDirectory();
        string clean = folder.Write("clean script.ps1", "Get-Date");
        string changed = folder.Write("changed.ps1", "Remove-Item 'demo-cache'");
        string report = Path.Combine(folder.Root, "batch-report.json");

        CliResult result = RunCli("--batch", clean, changed, "--json", report);

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("Analysis: PowerShell batch", result.Output);
        Assert.Contains("Files requested: 2", result.Output);
        Assert.Contains("Files analyzed: 2", result.Output);
        Assert.Contains("Findings: 1", result.Output);
        Assert.Contains("source was analyzed as text, not executed", result.Output);
        Assert.True(File.Exists(report));

        using JsonDocument json = JsonDocument.Parse(File.ReadAllText(report));
        JsonElement root = json.RootElement;
        Assert.Equal("batch", root.GetProperty("reportType").GetString());
        Assert.Equal(2, root.GetProperty("fileCount").GetInt32());
        Assert.Equal(clean, root.GetProperty("files")[0].GetProperty("fullPath").GetString());
        Assert.Equal(changed, root.GetProperty("files")[1].GetProperty("fullPath").GetString());
        Assert.False(root.GetProperty("sourceExecuted").GetBoolean());
    }

    [Fact]
    public void BatchMode_NeverExecutesSuppliedSource()
    {
        using var folder = new ScratchDirectory();
        string marker = Path.Combine(folder.Root, "DO-NOT-CREATE.txt");
        string escapedMarker = marker.Replace("'", "''");
        string script = folder.Write(
            "never-execute.ps1",
            $"Set-Content -LiteralPath '{escapedMarker}' -Value 'executed'\n" +
            "Invoke-Expression $source");

        CliResult result = RunCli("--batch", script);

        Assert.Equal(0, result.ExitCode);
        Assert.False(File.Exists(marker));
        Assert.Contains("Findings: 1", result.Output);
    }

    [Fact]
    public void BatchMode_FailOnFindingsReturnsOneAfterWritingReport()
    {
        using var folder = new ScratchDirectory();
        string clean = folder.Write("clean.ps1", "Get-Date");
        string changed = folder.Write("changed.ps1", "Invoke-Expression $source");
        string report = Path.Combine(folder.Root, "batch.json");

        CliResult result = RunCli(
            "--batch", clean, changed,
            "--json", report, "--fail-on-findings");

        Assert.Equal(1, result.ExitCode);
        Assert.True(File.Exists(report));
        Assert.Contains("Review required", result.Error);
    }

    [Fact]
    public void BatchMode_FailOnFindingsReturnsZeroForCleanFiles()
    {
        using var folder = new ScratchDirectory();
        string clean = folder.Write("clean.ps1", "Get-Date");
        CliResult result = RunCli("--batch", clean, "--fail-on-findings");
        Assert.Equal(0, result.ExitCode);
        Assert.Contains("Findings: 0", result.Output);
        Assert.Contains("does not establish safety", result.Output);
    }

    [Fact]
    public void BatchMode_ParserErrorIsIsolatedAndStrictModeReturnsThree()
    {
        using var folder = new ScratchDirectory();
        string malformed = folder.Write("malformed.ps1", "Write-Output 'unterminated");
        string valid = folder.Write("valid.ps1", "Get-Date");

        CliResult normal = RunCli("--batch", malformed, valid);
        CliResult strict = RunCli("--batch", malformed, valid, "--fail-on-findings");

        Assert.Equal(0, normal.ExitCode);
        Assert.Contains("Files with parser errors: 1", normal.Output);
        Assert.Contains("Analysis incomplete", normal.Output);
        Assert.Equal(3, strict.ExitCode);
        Assert.Contains("parser errors", strict.Error);
    }

    [Fact]
    public void BatchMode_InputErrorDoesNotPreventOtherFilesOrJson()
    {
        using var folder = new ScratchDirectory();
        string valid = folder.Write("valid.ps1", "Get-Date");
        string missing = Path.Combine(folder.Root, "missing.ps1");
        string report = Path.Combine(folder.Root, "batch.json");

        CliResult result = RunCli("--batch", valid, missing, "--json", report);

        Assert.Equal(2, result.ExitCode);
        Assert.Contains("Input errors: 1", result.Output);
        Assert.Contains("Files analyzed: 1", result.Output);
        Assert.True(File.Exists(report));
        using JsonDocument json = JsonDocument.Parse(File.ReadAllText(report));
        Assert.Equal("InputError",
            json.RootElement.GetProperty("files")[1].GetProperty("outcome").GetString());
    }

    [Fact]
    public void BatchMode_DuplicateFileReturnsInputError()
    {
        using var folder = new ScratchDirectory();
        string file = folder.Write("example.ps1", "Get-Date");

        CliResult result = RunCli("--batch", file, file);

        Assert.Equal(2, result.ExitCode);
        Assert.Contains("DuplicateInput", result.Output);
    }

    [Fact]
    public void BatchMode_RejectsUnrecognizedOptionsAndNoInput()
    {
        Assert.Equal(2, RunCli("--batch").ExitCode);
        Assert.Equal(2, RunCli("--batch", "--json", "report.json").ExitCode);
        Assert.Equal(2, RunCli("--batch", "a.ps1", "--unexpected").ExitCode);
        Assert.Equal(2, RunCli("--batch", "a.ps1", "--fail-on-findings", "--fail-on-findings").ExitCode);
    }

    [Fact]
    public void BatchMode_RejectsMoreThanFiftyInputsWithoutCreatingReport()
    {
        using var folder = new ScratchDirectory();
        string file = folder.Write("example.ps1", "Get-Date");
        string report = Path.Combine(folder.Root, "should-not-exist.json");
        var arguments = new List<string> { "--batch" };
        arguments.AddRange(Enumerable.Repeat(file, 51));
        arguments.Add("--json");
        arguments.Add(report);

        CliResult result = RunCli(arguments.ToArray());

        Assert.Equal(2, result.ExitCode);
        Assert.False(File.Exists(report));
        Assert.Contains("Usage:", result.Error);
    }

    [Fact]
    public void BatchMode_NeverOverwritesExistingReport()
    {
        using var folder = new ScratchDirectory();
        string file = folder.Write("example.ps1", "Get-Date");
        string report = folder.Write("report.json", "DO NOT OVERWRITE");

        CliResult result = RunCli("--batch", file, "--json", report);

        Assert.Equal(2, result.ExitCode);
        Assert.Equal("DO NOT OVERWRITE", File.ReadAllText(report));
        Assert.Contains("Report error", result.Error);
    }

    [Fact]
    public void BatchMode_DirectoryIsNotTreatedAsRecursiveScan()
    {
        using var folder = new ScratchDirectory();
        string valid = folder.Write("example.ps1", "Get-Date");

        CliResult result = RunCli("--batch", folder.Root, valid);

        Assert.Equal(2, result.ExitCode);
        Assert.Contains("Input errors: 1", result.Output);
        Assert.Contains("Files analyzed: 1", result.Output);
    }

    private static CliResult RunCli(params string[] arguments)
    {
        string root = FindRepositoryRoot();
        string configuration =
            new DirectoryInfo(AppContext.BaseDirectory).Parent!.Name;
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
            throw new TimeoutException("CLI timed out.");
        }
        return new CliResult(
            process.ExitCode,
            output.GetAwaiter().GetResult(),
            error.GetAwaiter().GetResult());
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
            Path.GetTempPath(), "bs-batch-cli-" + Guid.NewGuid().ToString("N"));

        public ScratchDirectory() => Directory.CreateDirectory(Root);

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
