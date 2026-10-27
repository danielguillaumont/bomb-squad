using System.Text;
using System.Text.Json.Nodes;
using BombSquad.Analysis;

namespace BombSquad.Tests;

/// <summary>
/// Final closeout regressions for report comparisons. These tests only create
/// files containing PowerShell source text; they never execute that source.
/// </summary>
public sealed class ComparisonCloseoutRegressionTests
{
    private readonly BatchReportComparisonService _service = new();

    [Fact]
    public void Compare_CleanIdenticalReportsHaveNoFindingDeltas()
    {
        using var fixture = new ReportFixture();
        string snapshot = fixture.Snapshot("Get-Date");

        BatchReportComparison result = _service.Compare(snapshot, snapshot);

        Assert.Equal(1, result.ComparedFileCount);
        Assert.Equal(0, result.IndeterminateFileCount);
        Assert.Equal(0, result.NewlyDetectedCount);
        Assert.Equal(0, result.StillDetectedCount);
        Assert.Equal(0, result.NoLongerDetectedCount);
        Assert.Empty(Assert.Single(result.Files).FindingChanges);
    }

    [Fact]
    public void Compare_EngineVersionMismatchIsIndeterminateNotResolved()
    {
        using var fixture = new ReportFixture();
        string baseline = fixture.Snapshot("Invoke-Expression $payload");
        JsonNode current = JsonNode.Parse(baseline)!;
        current["files"]![0]!["analysis"]!["engineVersion"] = "999.0-test";

        BatchReportComparison result = _service.Compare(baseline, current.ToJsonString());

        Assert.Equal(1, result.IndeterminateFileCount);
        Assert.Empty(Assert.Single(result.Files).FindingChanges);
        Assert.Equal(0, result.NoLongerDetectedCount);
        Assert.Equal(0, result.NewlyDetectedCount);
        Assert.Equal(0, result.StillDetectedCount);
    }

    [Fact]
    public void Compare_RejectsFabricatedFindingCount()
    {
        using var fixture = new ReportFixture();
        string baseline = fixture.Snapshot("Get-Date");
        JsonNode invalid = JsonNode.Parse(baseline)!;
        invalid["files"]![0]!["analysis"]!["findingCount"] = 1;

        Assert.Throws<ArgumentException>(() =>
            _service.Compare(baseline, invalid.ToJsonString()));
    }

    [Fact]
    public void Compare_RejectsMissingFindingEvidence()
    {
        using var fixture = new ReportFixture();
        string baseline = fixture.Snapshot("Invoke-Expression $payload");
        JsonNode invalid = JsonNode.Parse(baseline)!;
        invalid["files"]![0]!["analysis"]!["findings"]![0]!["evidence"] = null;

        Assert.Throws<ArgumentException>(() =>
            _service.Compare(invalid.ToJsonString(), baseline));
    }

    private sealed class ReportFixture : IDisposable
    {
        private readonly string _directory = Path.Combine(Path.GetTempPath(),
            "bs-closeout-" + Guid.NewGuid().ToString("N"));

        public ReportFixture() => Directory.CreateDirectory(_directory);

        public string Snapshot(string source)
        {
            string path = Path.Combine(_directory, "script.ps1");
            File.WriteAllText(path, source, new UTF8Encoding(false));
            return BatchJsonAnalysisReportWriter.Serialize(
                new BatchAnalysisService().AnalyzeFiles(new[] { path }));
        }

        public void Dispose()
        {
            if (Directory.Exists(_directory))
                Directory.Delete(_directory, recursive: true);
        }
    }
}
