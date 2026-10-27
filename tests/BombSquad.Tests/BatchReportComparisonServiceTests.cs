using System.Text;
using System.Text.Json.Nodes;
using BombSquad.Analysis;

namespace BombSquad.Tests;

public sealed class BatchReportComparisonServiceTests
{
    private readonly BatchReportComparisonService _service = new();

    [Fact]
    public void Compare_UnchangedEvidenceAtDifferentLineIsStillDetected()
    {
        using var folder = new TemporaryFolder();
        string path = folder.Write("example.ps1", "Remove-Item -LiteralPath 'cache'");
        string before = Report(path);
        folder.Write("example.ps1", "# Added comment\n\nRemove-Item -LiteralPath 'cache'");

        BatchReportComparison comparison = _service.Compare(before, Report(path));

        Assert.Equal(1, comparison.ComparedFileCount);
        Assert.Equal(1, comparison.StillDetectedCount);
        Assert.Equal(0, comparison.NewlyDetectedCount);
        Assert.Equal(0, comparison.NoLongerDetectedCount);
        Assert.Equal(FindingChangeKind.StillDetected,
            Assert.Single(Assert.Single(comparison.Files).FindingChanges).Kind);
    }

    [Fact]
    public void Compare_ReportsNewFindingWithoutClaimingExecution()
    {
        using var folder = new TemporaryFolder();
        string path = folder.Write("example.ps1", "Get-Date");
        string before = Report(path);
        folder.Write("example.ps1", "Get-Date\nInvoke-Expression $code");

        BatchReportComparison comparison = _service.Compare(before, Report(path));

        Assert.Equal(1, comparison.NewlyDetectedCount);
        Assert.Equal(0, comparison.NoLongerDetectedCount);
        FindingChange change = Assert.Single(Assert.Single(comparison.Files).FindingChanges);
        Assert.Equal("BS-DE-001", change.RuleId);
        Assert.Equal(FindingChangeKind.NewlyDetected, change.Kind);
        Assert.Contains(comparison.Limitations, limitation =>
            limitation.Contains("not proof", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Compare_ReportsNoLongerDetectedInsteadOfSafeOrResolved()
    {
        using var folder = new TemporaryFolder();
        string path = folder.Write("example.ps1", "Invoke-Expression $code");
        string before = Report(path);
        folder.Write("example.ps1", "Get-Date");

        BatchReportComparison comparison = _service.Compare(before, Report(path));

        Assert.Equal(1, comparison.NoLongerDetectedCount);
        Assert.Equal(FindingChangeKind.NoLongerDetected,
            Assert.Single(Assert.Single(comparison.Files).FindingChanges).Kind);
        Assert.Contains(comparison.Limitations, limitation =>
            limitation.Contains("does not establish", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Compare_RepeatedEvidenceIsMatchedAsMultiset()
    {
        using var folder = new TemporaryFolder();
        string path = folder.Write("example.ps1",
            "Invoke-Expression $code\nInvoke-Expression $code");
        string before = Report(path);
        folder.Write("example.ps1", "Invoke-Expression $code");

        BatchReportComparison comparison = _service.Compare(before, Report(path));

        Assert.Equal(1, comparison.StillDetectedCount);
        Assert.Equal(1, comparison.NoLongerDetectedCount);
        Assert.Equal(0, comparison.NewlyDetectedCount);
        Assert.Equal(2, Assert.Single(comparison.Files).FindingChanges.Length);
    }

    [Fact]
    public void Compare_ChangedEvidenceIsNewAndNoLongerDetected()
    {
        using var folder = new TemporaryFolder();
        string path = folder.Write("example.ps1", "Remove-Item -LiteralPath 'old'");
        string before = Report(path);
        folder.Write("example.ps1", "Remove-Item -LiteralPath 'new'");

        BatchReportComparison comparison = _service.Compare(before, Report(path));

        Assert.Equal(1, comparison.NewlyDetectedCount);
        Assert.Equal(1, comparison.NoLongerDetectedCount);
        Assert.Equal(0, comparison.StillDetectedCount);
    }

    [Fact]
    public void Compare_CurrentParserFailureMakesFindingChangesIndeterminate()
    {
        using var folder = new TemporaryFolder();
        string path = folder.Write("example.ps1", "Invoke-Expression $code");
        string before = Report(path);
        folder.Write("example.ps1", "Write-Output 'unterminated");

        BatchReportComparison comparison = _service.Compare(before, Report(path));

        ComparedFile file = Assert.Single(comparison.Files);
        Assert.Equal(ComparedFileStatus.Indeterminate, file.Status);
        Assert.Empty(file.FindingChanges);
        Assert.Equal(0, comparison.NoLongerDetectedCount);
        Assert.Equal(1, comparison.IndeterminateFileCount);
        Assert.True(file.CurrentDiagnosticCount > 0);
    }

    [Fact]
    public void Compare_InputFailureMakesFindingChangesIndeterminate()
    {
        using var folder = new TemporaryFolder();
        string path = folder.Write("example.ps1", "Invoke-Expression $code");
        string before = Report(path);
        File.Delete(path);

        BatchReportComparison comparison = _service.Compare(before, Report(path));

        Assert.Equal(ComparedFileStatus.Indeterminate, Assert.Single(comparison.Files).Status);
        Assert.Equal(0, comparison.NoLongerDetectedCount);
    }

    [Fact]
    public void Compare_DifferentRuleSetVersionMakesChangesIndeterminate()
    {
        using var folder = new TemporaryFolder();
        string path = folder.Write("example.ps1", "Invoke-Expression $code");
        string before = Report(path);
        string after = Report(path);
        JsonNode current = JsonNode.Parse(after)!;
        current["files"]![0]!["analysis"]!["ruleSetVersion"] = "99.0.0";

        BatchReportComparison comparison = _service.Compare(before, current.ToJsonString());

        ComparedFile file = Assert.Single(comparison.Files);
        Assert.Equal(ComparedFileStatus.Indeterminate, file.Status);
        Assert.Contains("version", file.Explanation, StringComparison.OrdinalIgnoreCase);
        Assert.Empty(file.FindingChanges);
    }

    [Fact]
    public void Compare_FilesMissingFromEitherSnapshotAreNotCalledFindingChanges()
    {
        using var folder = new TemporaryFolder();
        string oldPath = folder.Write("old.ps1", "Invoke-Expression $old");
        string newPath = folder.Write("new.ps1", "Remove-Item 'cache'");

        BatchReportComparison comparison = _service.Compare(Report(oldPath), Report(newPath));

        Assert.Equal(1, comparison.OnlyInBaselineCount);
        Assert.Equal(1, comparison.OnlyInCurrentCount);
        Assert.Equal(0, comparison.NewlyDetectedCount);
        Assert.Equal(0, comparison.NoLongerDetectedCount);
        Assert.All(comparison.Files, file => Assert.Empty(file.FindingChanges));
    }

    [Fact]
    public void Compare_BatchWithOtherMalformedFileStillComparesValidFile()
    {
        using var folder = new TemporaryFolder();
        string valid = folder.Write("valid.ps1", "Get-Date");
        string malformed = folder.Write("bad.ps1", "Write-Output 'unterminated");
        string before = Report(valid, malformed);
        folder.Write("valid.ps1", "Invoke-Expression $payload");

        BatchReportComparison comparison = _service.Compare(before, Report(valid, malformed));

        Assert.Equal(1, comparison.ComparedFileCount);
        Assert.Equal(1, comparison.IndeterminateFileCount);
        Assert.Equal(1, comparison.NewlyDetectedCount);
    }

    [Fact]
    public void Compare_AcceptsDuplicateInputErrorProducedByBatchWriter()
    {
        using var folder = new TemporaryFolder();
        string path = folder.Write("same.ps1", "Get-Date");
        string report = Report(path, path);

        BatchReportComparison comparison = _service.Compare(report, report);

        Assert.Equal(1, comparison.ComparedFileCount);
        Assert.Single(comparison.Files);
    }

    [Fact]
    public void Compare_EmptyRequestedPathInputErrorDoesNotInvalidateWholeReport()
    {
        using var folder = new TemporaryFolder();
        string valid = folder.Write("valid.ps1", "Invoke-Expression $code");
        string snapshot = Report(valid, "");

        BatchReportComparison comparison = _service.Compare(snapshot, snapshot);

        Assert.Equal(1, comparison.ComparedFileCount);
        Assert.Equal(1, comparison.IndeterminateFileCount);
        Assert.Equal(1, comparison.StillDetectedCount);
    }

    [Fact]
    public void Compare_WindowsFileIdentitiesIgnoreDriveLetterCase()
    {
        using var folder = new TemporaryFolder();
        string path = folder.Write("example.ps1", "Get-Date");
        JsonNode before = JsonNode.Parse(Report(path))!;
        JsonNode after = JsonNode.Parse(Report(path))!;
        before["files"]![0]!["fullPath"] = @"C:\Samples\SAMPLE.ps1";
        after["files"]![0]!["fullPath"] = @"c:\samples\sample.ps1";

        BatchReportComparison comparison = _service.Compare(
            before.ToJsonString(), after.ToJsonString());

        Assert.Equal(1, comparison.ComparedFileCount);
        Assert.Equal(0, comparison.OnlyInBaselineCount);
    }

    [Fact]
    public void Compare_RejectsNonBatchJsonAndInvalidInput()
    {
        using var folder = new TemporaryFolder();
        string script = folder.Write("example.ps1", "Get-Date");
        string valid = Report(script);

        Assert.Throws<ArgumentException>(() => _service.Compare("{broken", valid));
        Assert.Throws<ArgumentException>(() => _service.Compare("{}", valid));
        Assert.Throws<ArgumentException>(() => _service.Compare(valid, "[]"));
        Assert.Throws<ArgumentException>(() => _service.Compare(
            new string('x', BatchReportComparisonService.MaximumReportCharacters + 1), valid));
    }

    [Fact]
    public void Compare_RejectsReportsClaimingExecutedSource()
    {
        using var folder = new TemporaryFolder();
        string path = folder.Write("example.ps1", "Get-Date");
        string valid = Report(path);
        JsonNode outer = JsonNode.Parse(valid)!;
        outer["sourceExecuted"] = true;
        Assert.Throws<ArgumentException>(() => _service.Compare(outer.ToJsonString(), valid));

        JsonNode nested = JsonNode.Parse(valid)!;
        nested["files"]![0]!["analysis"]!["sourceExecuted"] = true;
        Assert.Throws<ArgumentException>(() => _service.Compare(valid, nested.ToJsonString()));
    }

    [Fact]
    public void Compare_UsesSavedSnapshotsWithoutReadingCurrentScript()
    {
        using var folder = new TemporaryFolder();
        string path = folder.Write("example.ps1", "Invoke-Expression $code");
        string before = Report(path);
        string after = Report(path);
        File.Delete(path);

        BatchReportComparison comparison = _service.Compare(before, after);

        Assert.Equal(1, comparison.StillDetectedCount);
        Assert.False(File.Exists(path));
    }

    private static string Report(params string[] paths) =>
        BatchJsonAnalysisReportWriter.Serialize(
            new BatchAnalysisService().AnalyzeFiles(paths));

    private sealed class TemporaryFolder : IDisposable
    {
        public string Root { get; } = Path.Combine(Path.GetTempPath(),
            "bs-comparison-tests-" + Guid.NewGuid().ToString("N"));

        public TemporaryFolder() => Directory.CreateDirectory(Root);

        public string Write(string name, string source)
        {
            string path = Path.Combine(Root, name);
            File.WriteAllText(path, source, new UTF8Encoding(false));
            return path;
        }

        public void Dispose()
        {
            if (Directory.Exists(Root)) Directory.Delete(Root, recursive: true);
        }
    }
}
