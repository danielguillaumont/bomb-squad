using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using BombSquad.Analysis;
using BombSquad.Core;

namespace BombSquad.Tests;

/// <summary>
/// v0.9 release-candidate integration checks against the actual v0.8 public
/// analysis/report contracts. All PowerShell in these tests is DATA ONLY;
/// the test process never invokes PowerShell to run inspected source.
/// </summary>
public sealed class V09ReleaseCandidateGateTests
{
    private static AnalysisResult Inspect(string source) => new AnalysisService()
        .Analyze(new AnalysisRequest(source, "rc-test.ps1"));

    [Fact]
    public void RC01_CleanInputDoesNotCreateAnUnsafeSafetyVerdict()
    {
        AnalysisResult result = Inspect("Get-Date");
        using JsonDocument document = JsonDocument.Parse(
            JsonAnalysisReportWriter.Serialize("rc-test.ps1", result));

        Assert.Equal(AnalysisStatus.Parsed, result.Status);
        Assert.Empty(result.Findings);
        Assert.False(document.RootElement.GetProperty("sourceExecuted").GetBoolean());
        Assert.Equal(0, document.RootElement.GetProperty("findingCount").GetInt32());
        Assert.Contains(result.Limitations, limitation => limitation.Contains(
            "absence of findings does not establish safety", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void RC02_InspectingDangerousLookingTextDoesNotExecutePowerShell()
    {
        using var fixture = new SourceFixture();
        string marker = fixture.PathFor("must-not-exist.marker");
        string escaped = marker.Replace("'", "''", StringComparison.Ordinal);
        string source =
            $"Set-Content -LiteralPath '{escaped}' -Value 'executed'\n" +
            "Invoke-Expression $candidate";

        AnalysisResult result = Inspect(source);

        Assert.Equal(AnalysisStatus.Parsed, result.Status);
        Assert.Contains(result.Findings, finding => finding.RuleId == "BS-DE-001");
        Assert.False(File.Exists(marker));
    }

    [Fact]
    public void RC03_PastedInputPreservesExactEvidenceSpans()
    {
        const string source = "  Write-Output 'caf\u00e9'\r\n  Remove-Item -LiteralPath 'cache'";
        string validated = PastedPowerShellInput.Validate(source);
        AnalysisResult result = Inspect(validated);
        Finding finding = Assert.Single(result.Findings);

        Assert.Equal(source, validated);
        Assert.Equal("BS-FS-001", finding.RuleId);
        Assert.Equal(2, finding.SourceSpan.StartLine);
        Assert.Equal(3, finding.SourceSpan.StartColumn);
        Assert.Equal(finding.Evidence, source.Substring(
            finding.SourceSpan.StartOffset, finding.SourceSpan.Length));
    }

    [Fact]
    public void RC04_FileReaderAndBatchInspectionNeverRunTheSource()
    {
        using var fixture = new SourceFixture();
        string marker = fixture.PathFor("not-created.marker");
        string escaped = marker.Replace("'", "''", StringComparison.Ordinal);
        string path = fixture.WriteScript("untrusted.ps1",
            $"Set-Content -LiteralPath '{escaped}' -Value 'ran'\n" +
            "Invoke-Expression $candidate");

        PowerShellScriptFile read = PowerShellScriptFileReader.Read(path);
        BatchAnalysisResult batch = new BatchAnalysisService().AnalyzeFiles(new[] { path });

        Assert.Equal(path, read.FullPath);
        Assert.Equal(read.SourceText, Assert.Single(batch.Files).SourceText);
        Assert.Contains(Assert.Single(batch.Files).Result!.Findings,
            finding => finding.RuleId == "BS-DE-001");
        Assert.False(File.Exists(marker));
    }

    [Fact]
    public void RC05_BatchPreservesIndependentParserAndInputFailures()
    {
        using var fixture = new SourceFixture();
        string valid = fixture.WriteScript("valid.ps1", "Remove-Item -Path 'demo'");
        string malformed = fixture.WriteScript("malformed.ps1", "Write-Output 'unfinished");
        string missing = fixture.PathFor("missing.ps1");

        BatchAnalysisResult batch = new BatchAnalysisService()
            .AnalyzeFiles(new[] { valid, malformed, missing });
        using JsonDocument document = JsonDocument.Parse(
            BatchJsonAnalysisReportWriter.Serialize(batch));

        Assert.Equal(3, batch.FileCount);
        Assert.Equal(2, batch.AnalyzedFileCount);
        Assert.Equal(1, batch.InputErrorCount);
        Assert.Equal(1, batch.ParserErrorFileCount);
        Assert.Equal(1, batch.TotalFindingCount);
        Assert.False(batch.AllFilesAnalyzed);
        Assert.Equal("BS-FS-001", Assert.Single(batch.Files[0].Result!.Findings).RuleId);
        Assert.True(batch.Files[1].Result!.RulesSkipped);
        Assert.Empty(batch.Files[1].Result!.Findings);
        Assert.Equal("FileNotFound", batch.Files[2].InputError!.Code);
        Assert.False(document.RootElement.GetProperty("sourceExecuted").GetBoolean());
        Assert.False(document.RootElement.GetProperty("allFilesAnalyzed").GetBoolean());
    }

    [Fact]
    public void RC06_BatchReportDoesNotEmbedUnmatchedFullScriptText()
    {
        using var fixture = new SourceFixture();
        const string token = "PRIVATE_TEST_VALUE_NOT_FOR_REPORT_6f0a";
        string file = fixture.WriteScript("unmatched.ps1",
            $"Write-Output '{token}'\nGet-Date");
        BatchAnalysisResult batch = new BatchAnalysisService().AnalyzeFiles(new[] { file });

        string json = BatchJsonAnalysisReportWriter.Serialize(batch);

        Assert.True(batch.AllFilesAnalyzed);
        Assert.Empty(Assert.Single(batch.Files).Result!.Findings);
        Assert.DoesNotContain(token, json, StringComparison.Ordinal);
        using JsonDocument document = JsonDocument.Parse(json);
        Assert.Equal(file, document.RootElement.GetProperty("files")[0]
            .GetProperty("fullPath").GetString());
    }

    [Fact]
    public void RC07_BatchKeepsTheOriginalAnalyzedSnapshotInMemory()
    {
        using var fixture = new SourceFixture();
        const string original = "Remove-Item -LiteralPath 'original-cache'";
        string file = fixture.WriteScript("changing.ps1", original);

        BatchAnalysisResult batch = new BatchAnalysisService().AnalyzeFiles(new[] { file });
        fixture.WriteScript("changing.ps1", "Get-Date");

        Assert.Equal(original, Assert.Single(batch.Files).SourceText);
        Assert.Equal("BS-FS-001", Assert.Single(batch.Files[0].Result!.Findings).RuleId);
    }

    [Fact]
    public void RC08_RealBatchReportsIdentifyNewFindingAfterSourceChange()
    {
        using var fixture = new SourceFixture();
        string file = fixture.WriteScript("inspect.ps1", "Get-Date");
        string baseline = Snapshot(file);
        fixture.WriteScript("inspect.ps1", "Remove-Item -LiteralPath 'cache'");
        string current = Snapshot(file);

        BatchReportComparison delta = new BatchReportComparisonService()
            .Compare(baseline, current);
        using JsonDocument document = JsonDocument.Parse(
            BatchReportComparisonJsonWriter.Serialize(delta));

        Assert.Equal(1, delta.ComparedFileCount);
        Assert.Equal(1, delta.NewlyDetectedCount);
        Assert.Equal(0, delta.NoLongerDetectedCount);
        Assert.Equal(FindingChangeKind.NewlyDetected,
            Assert.Single(Assert.Single(delta.Files).FindingChanges).Kind);
        Assert.False(document.RootElement.GetProperty("sourceExecuted").GetBoolean());
    }

    [Fact]
    public void RC09_DisappearingFindingMustNotBecomeASafetyVerdict()
    {
        using var fixture = new SourceFixture();
        string file = fixture.WriteScript("inspect.ps1", "Remove-Item -Path 'cache'");
        string baseline = Snapshot(file);
        fixture.WriteScript("inspect.ps1", "Get-Date");
        string current = Snapshot(file);

        BatchReportComparison delta = new BatchReportComparisonService()
            .Compare(baseline, current);

        Assert.Equal(1, delta.ComparedFileCount);
        Assert.Equal(1, delta.NoLongerDetectedCount);
        Assert.Equal(0, delta.NewlyDetectedCount);
        Assert.Contains(delta.Limitations, limitation => limitation.Contains(
            "does not establish", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void RC10_MalformedCurrentScriptMustNotBeReportedAsRemediated()
    {
        using var fixture = new SourceFixture();
        string file = fixture.WriteScript("inspect.ps1", "Remove-Item 'cache'");
        string baseline = Snapshot(file);
        fixture.WriteScript("inspect.ps1", "Write-Output 'unterminated");
        string current = Snapshot(file);

        BatchReportComparison delta = new BatchReportComparisonService()
            .Compare(baseline, current);

        Assert.Equal(1, delta.IndeterminateFileCount);
        Assert.Equal(0, delta.NoLongerDetectedCount);
        Assert.Equal(0, delta.NewlyDetectedCount);
        Assert.Empty(Assert.Single(delta.Files).FindingChanges);
    }

    [Fact]
    public void RC11_ComparisonOperatesOnJSONWithoutReopeningPowerShellFiles()
    {
        using var fixture = new SourceFixture();
        string file = fixture.WriteScript("inspect.ps1", "Get-Date");
        string baseline = Snapshot(file);
        fixture.WriteScript("inspect.ps1", "Invoke-Expression $text");
        string current = Snapshot(file);
        File.Delete(file);

        BatchReportComparison delta = new BatchReportComparisonService()
            .Compare(baseline, current);

        Assert.False(File.Exists(file));
        Assert.Equal(1, delta.NewlyDetectedCount);
        Assert.Equal(1, delta.ComparedFileCount);
    }

    [Fact]
    public void RC12_ForgedExecutedFlagIsRejectedDuringComparison()
    {
        using var fixture = new SourceFixture();
        string file = fixture.WriteScript("inspect.ps1", "Get-Date");
        string baseline = Snapshot(file);
        JsonNode forged = JsonNode.Parse(baseline)!;
        forged["sourceExecuted"] = true;

        Assert.Throws<ArgumentException>(() => new BatchReportComparisonService()
            .Compare(baseline, forged.ToJsonString()));
    }

    [Fact]
    public void RC13_IncompatibleEngineVersionIsIndeterminate()
    {
        using var fixture = new SourceFixture();
        string file = fixture.WriteScript("inspect.ps1", "Remove-Item 'cache'");
        string baseline = Snapshot(file);
        JsonNode changed = JsonNode.Parse(baseline)!;
        changed["files"]![0]!["analysis"]!["engineVersion"] = "different-engine";

        BatchReportComparison delta = new BatchReportComparisonService()
            .Compare(baseline, changed.ToJsonString());

        Assert.Equal(1, delta.IndeterminateFileCount);
        Assert.Equal(0, delta.NoLongerDetectedCount);
        Assert.Equal(0, delta.StillDetectedCount);
    }

    [Fact]
    public void RC14_AllThreeJsonExportModesRefuseToOverwriteAnExistingFile()
    {
        using var fixture = new SourceFixture();
        string script = fixture.WriteScript("inspect.ps1", "Get-Date");
        AnalysisResult single = Inspect("Get-Date");
        BatchAnalysisResult batch = new BatchAnalysisService()
            .AnalyzeFiles(new[] { script });
        string snapshot = BatchJsonAnalysisReportWriter.Serialize(batch);
        BatchReportComparison comparison = new BatchReportComparisonService()
            .Compare(snapshot, snapshot);

        Action<string>[] exports =
        {
            path => { _ = JsonAnalysisReportWriter.WriteNew(path, script, single); },
            path => { _ = BatchJsonAnalysisReportWriter.WriteNew(path, batch); },
            path => { _ = BatchReportComparisonJsonWriter.WriteNew(path, comparison); }
        };

        for (int i = 0; i < exports.Length; i++)
        {
            string destination = fixture.PathFor($"existing-{i}.json");
            File.WriteAllText(destination, "PRESERVE_EXISTING_REPORT", new UTF8Encoding(false));

            Assert.Throws<IOException>(() => exports[i](destination));
            Assert.Equal("PRESERVE_EXISTING_REPORT", File.ReadAllText(destination));
        }
    }

    private static string Snapshot(string path) =>
        BatchJsonAnalysisReportWriter.Serialize(
            new BatchAnalysisService().AnalyzeFiles(new[] { path }));

    private sealed class SourceFixture : IDisposable
    {
        private readonly string _directory = Path.Combine(Path.GetTempPath(),
            "bomb-squad-v09-rc-" + Guid.NewGuid().ToString("N"));

        public SourceFixture() => Directory.CreateDirectory(_directory);

        public string PathFor(string fileName) => Path.Combine(_directory, fileName);

        public string WriteScript(string fileName, string source)
        {
            string path = PathFor(fileName);
            File.WriteAllText(path, source, new UTF8Encoding(false));
            return path;
        }

        public void Dispose()
        {
            if (Directory.Exists(_directory))
            {
                Directory.Delete(_directory, recursive: true);
            }
        }
    }
}
