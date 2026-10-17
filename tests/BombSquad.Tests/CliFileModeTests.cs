using System.Diagnostics;
using System.Text;

namespace BombSquad.Tests;

public sealed class CliFileModeTests
{
    [Fact]
    public void FileMode_DetectsFindingsWithoutExecutingSource()
    {
        using var folder = new ScratchDirectory();

        string marker = Path.Combine(folder.Root, "execution-marker.txt");
        string escapedMarker = marker.Replace("'", "''");

        string file = folder.Write(
            "script with spaces.ps1",
            $"Set-Content -LiteralPath '{escapedMarker}' -Value 'executed'\n" +
            "Invoke-Expression $source\n" +
            "& $operation"
        );

        CliResult result = RunCli("--file", file);

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("Analysis: PowerShell file", result.Output);
        Assert.Contains("Status: Parsed", result.Output);
        Assert.Contains("Findings: 2", result.Output);
        Assert.Contains("[BS-DE-001]", result.Output);
        Assert.Contains("Line 2, Column 1", result.Output);
        Assert.Contains("Line 3, Column 1", result.Output);
        Assert.False(File.Exists(marker));
    }

    [Fact]
    public void FileMode_MalformedScriptSkipsRules()
    {
        using var folder = new ScratchDirectory();

        string file = folder.Write(
            "malformed.ps1",
            "Invoke-Expression $source\nWrite-Output 'unterminated"
        );

        CliResult result = RunCli("--file", file);

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("Status: ParsedWithErrors", result.Output);
        Assert.Contains("Rules skipped: True", result.Output);
        Assert.Contains("Findings: 0", result.Output);
    }

    [Fact]
    public void FileMode_RejectsMissingFile()
    {
        using var folder = new ScratchDirectory();

        string missing = Path.Combine(folder.Root, "missing.ps1");

        CliResult result = RunCli("--file", missing);

        Assert.Equal(2, result.ExitCode);
        Assert.Contains("file not found", result.Error);
    }

    [Fact]
    public void FileMode_RejectsNonPowerShellExtension()
    {
        using var folder = new ScratchDirectory();

        string file = folder.Write("sample.txt", "Get-Date");

        CliResult result = RunCli("--file", file);

        Assert.Equal(2, result.ExitCode);
        Assert.Contains("only .ps1 files", result.Error);
    }

    [Fact]
    public void FileMode_RejectsOversizedInput()
    {
        using var folder = new ScratchDirectory();

        string file = Path.Combine(folder.Root, "large.ps1");

        File.WriteAllBytes(file, new byte[1024 * 1024 + 1]);

        CliResult result = RunCli("--file", file);

        Assert.Equal(2, result.ExitCode);
        Assert.Contains("1 MiB limit", result.Error);
    }

    [Fact]
    public void FileMode_RejectsInvalidUtf8()
    {
        using var folder = new ScratchDirectory();

        string file = Path.Combine(folder.Root, "invalid.ps1");

        File.WriteAllBytes(file, new byte[] { 0xC3, 0x28 });

        CliResult result = RunCli("--file", file);

        Assert.Equal(2, result.ExitCode);
        Assert.Contains("Input error:", result.Error);
    }

    [Fact]
    public void FileMode_ReadsUtf16WithBom()
    {
        using var folder = new ScratchDirectory();

        string file = folder.Write(
            "unicode.ps1",
            "Get-Date",
            Encoding.Unicode
        );

        CliResult result = RunCli("--file", file);

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("Status: Parsed", result.Output);
        Assert.Contains("Get-Date", result.Output);
        Assert.Contains("Findings: 0", result.Output);
    }

    [Fact]
    public void FileMode_EmptyScriptDoesNotClaimSafety()
    {
        using var folder = new ScratchDirectory();

        string file = folder.Write("empty.ps1", "");

        CliResult result = RunCli("--file", file);

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("Findings: 0", result.Output);
        Assert.Contains("does not establish safety", result.Output);
    }

    [Fact]
    public void DefaultDemoStillReportsSixFindings()
    {
        CliResult result = RunCli();

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("Demo: Six detection families", result.Output);
        Assert.Contains("Findings: 6", result.Output);
    }

    [Fact]
    public void MalformedDemoStillSkipsRules()
    {
        CliResult result = RunCli("--demo-malformed");

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("Status: ParsedWithErrors", result.Output);
        Assert.Contains("Rules skipped: True", result.Output);
        Assert.Contains("Findings: 0", result.Output);
    }

    [Fact]
    public void MissingFileArgumentShowsUsage()
    {
        CliResult result = RunCli("--file");

        Assert.Equal(2, result.ExitCode);
        Assert.Contains("Usage:", result.Error);
    }

    private static CliResult RunCli(params string[] arguments)
    {
        string root = FindRepositoryRoot();

        string configuration =
            new DirectoryInfo(AppContext.BaseDirectory).Parent!.Name;

        string cliAssembly = Path.Combine(
            root,
            "src",
            "BombSquad.Cli",
            "bin",
            configuration,
            "net10.0",
            "BombSquad.Cli.dll"
        );

        Assert.True(
            File.Exists(cliAssembly),
            $"CLI assembly missing: {cliAssembly}. Build the solution first."
        );

        var start = new ProcessStartInfo
        {
            FileName =
                Environment.GetEnvironmentVariable("DOTNET_HOST_PATH")
                ?? "dotnet",
            WorkingDirectory = root,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };

        start.ArgumentList.Add(cliAssembly);

        foreach (string argument in arguments)
        {
            start.ArgumentList.Add(argument);
        }

        using var process = new Process { StartInfo = start };

        if (!process.Start())
        {
            throw new InvalidOperationException("Could not start the CLI.");
        }

        Task<string> outputTask = process.StandardOutput.ReadToEndAsync();
        Task<string> errorTask = process.StandardError.ReadToEndAsync();

        if (!process.WaitForExit(20000))
        {
            process.Kill(entireProcessTree: true);
            throw new TimeoutException("CLI did not exit within 20 seconds.");
        }

        return new CliResult(
            process.ExitCode,
            outputTask.GetAwaiter().GetResult(),
            errorTask.GetAwaiter().GetResult()
        );
    }

    private static string FindRepositoryRoot()
    {
        DirectoryInfo? directory =
            new DirectoryInfo(AppContext.BaseDirectory);

        while (directory is not null)
        {
            if (File.Exists(
                Path.Combine(directory.FullName, "BombSquad.slnx")
            ))
            {
                return directory.FullName;
            }

            directory = directory.Parent;
        }

        throw new DirectoryNotFoundException(
            "Could not locate the BOMB SQUAD repository."
        );
    }

    private sealed record CliResult(
        int ExitCode,
        string Output,
        string Error
    );

    private sealed class ScratchDirectory : IDisposable
    {
        public string Root { get; } = Path.Combine(
            Path.GetTempPath(),
            "Bomb Squad CLI Tests " + Guid.NewGuid().ToString("N")
        );

        public ScratchDirectory()
        {
            Directory.CreateDirectory(Root);
        }

        public string Write(
            string name,
            string content,
            Encoding? encoding = null)
        {
            string path = Path.Combine(Root, name);

            File.WriteAllText(
                path,
                content,
                encoding ?? new UTF8Encoding(false)
            );

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
