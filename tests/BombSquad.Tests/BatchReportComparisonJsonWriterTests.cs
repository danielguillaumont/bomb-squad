using System.Collections.Immutable;
using System.Text.Json;
using BombSquad.Analysis;

namespace BombSquad.Tests;

public sealed class BatchReportComparisonJsonWriterTests
{
    [Fact]
    public void Serialize_ContainsDeterministicTotalsAndCategorizedFindings()
    {
        BatchReportComparison comparison = SampleComparison();

        using JsonDocument document = JsonDocument.Parse(
            BatchReportComparisonJsonWriter.Serialize(comparison));
        JsonElement root = document.RootElement;

        Assert.Equal("0.1.0", root.GetProperty("schemaVersion").GetString());
        Assert.Equal("comparison", root.GetProperty("reportType").GetString());
        Assert.Equal(3, root.GetProperty("fileCount").GetInt32());
        Assert.Equal(1, root.GetProperty("comparedFileCount").GetInt32());
        Assert.Equal(1, root.GetProperty("indeterminateFileCount").GetInt32());
        Assert.Equal(1, root.GetProperty("onlyInBaselineCount").GetInt32());
        Assert.Equal(0, root.GetProperty("onlyInCurrentCount").GetInt32());
        Assert.Equal(2, root.GetProperty("newlyDetectedCount").GetInt32());
        Assert.Equal(1, root.GetProperty("stillDetectedCount").GetInt32());
        Assert.Equal(1, root.GetProperty("noLongerDetectedCount").GetInt32());
        Assert.False(root.GetProperty("sourceExecuted").GetBoolean());

        JsonElement compared = root.GetProperty("files")[0];
        Assert.Equal("Compared", compared.GetProperty("status").GetString());
        Assert.Equal(@"C:\Scripts\example.ps1",
            compared.GetProperty("filePath").GetString());
        Assert.Equal(3, compared.GetProperty("findingChanges").GetArrayLength());
        Assert.Equal("BS-DE-001",
            compared.GetProperty("findingChanges")[0].GetProperty("ruleId").GetString());
        Assert.Equal("NewlyDetected",
            compared.GetProperty("findingChanges")[0].GetProperty("kind").GetString());
        Assert.Equal(2,
            compared.GetProperty("findingChanges")[0].GetProperty("count").GetInt32());
    }

    [Fact]
    public void Serialize_IndeterminateAndUnpairedFilesHaveNoInventedFindingChanges()
    {
        using JsonDocument document = JsonDocument.Parse(
            BatchReportComparisonJsonWriter.Serialize(SampleComparison()));
        JsonElement entries = document.RootElement.GetProperty("files");

        Assert.Equal("Indeterminate", entries[1].GetProperty("status").GetString());
        Assert.Equal(0, entries[1].GetProperty("findingChanges").GetArrayLength());
        Assert.Equal(JsonValueKind.Null,
            entries[1].GetProperty("currentFindingCount").ValueKind);
        Assert.Equal("OnlyInBaseline", entries[2].GetProperty("status").GetString());
        Assert.Equal(0, entries[2].GetProperty("findingChanges").GetArrayLength());
        Assert.Equal(JsonValueKind.Null,
            entries[2].GetProperty("currentFindingCount").ValueKind);
        Assert.Contains(document.RootElement.GetProperty("limitations").EnumerateArray(),
            limitation => limitation.GetString()!.Contains("not proof", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Serialize_IsStableAcrossCalls()
    {
        BatchReportComparison comparison = SampleComparison();
        Assert.Equal(BatchReportComparisonJsonWriter.Serialize(comparison),
            BatchReportComparisonJsonWriter.Serialize(comparison));
    }

    [Fact]
    public void WriteNew_WritesUtf8WithoutBomAndReturnsAbsolutePath()
    {
        using var folder = new TemporaryFolder();
        string output = Path.Combine(folder.Root, "comparison.json");

        string saved = BatchReportComparisonJsonWriter.WriteNew(
            output, SampleComparison());

        Assert.Equal(Path.GetFullPath(output), saved);
        byte[] bytes = File.ReadAllBytes(output);
        Assert.NotEmpty(bytes);
        Assert.Equal((byte)'{', bytes[0]);
        using JsonDocument document = JsonDocument.Parse(bytes);
        Assert.Equal("comparison",
            document.RootElement.GetProperty("reportType").GetString());
    }

    [Fact]
    public void WriteNew_RejectsOverwriteWithoutChangingExistingData()
    {
        using var folder = new TemporaryFolder();
        string output = Path.Combine(folder.Root, "existing.json");
        File.WriteAllText(output, "KEEP ORIGINAL");

        Assert.Throws<IOException>(() =>
            BatchReportComparisonJsonWriter.WriteNew(output, SampleComparison()));

        Assert.Equal("KEEP ORIGINAL", File.ReadAllText(output));
    }

    [Fact]
    public void WriteNew_RejectsNonJsonExtension()
    {
        using var folder = new TemporaryFolder();
        string output = Path.Combine(folder.Root, "comparison.txt");

        Assert.Throws<ArgumentException>(() =>
            BatchReportComparisonJsonWriter.WriteNew(output, SampleComparison()));
        Assert.False(File.Exists(output));
    }

    [Fact]
    public void Serialize_RejectsNullComparison()
    {
        Assert.Throws<ArgumentNullException>(() =>
            BatchReportComparisonJsonWriter.Serialize(null!));
    }

    private static BatchReportComparison SampleComparison() => new(
        ImmutableArray.Create(
            new ComparedFile(
                @"C:\Scripts\example.ps1",
                ComparedFileStatus.Compared,
                "Matching engine and rule set.",
                ImmutableArray.Create(
                    new FindingChange("BS-DE-001", "Potential dynamic execution",
                        "Invoke-Expression $code", FindingChangeKind.NewlyDetected, 2),
                    new FindingChange("BS-FS-001", "Potential item deletion",
                        "Remove-Item 'cache'", FindingChangeKind.StillDetected, 1),
                    new FindingChange("BS-ID-001", "Potential identity change",
                        "Add-LocalGroupMember", FindingChangeKind.NoLongerDetected, 1)),
                2, 3, 0, 0),
            new ComparedFile(
                @"C:\Scripts\broken.ps1",
                ComparedFileStatus.Indeterminate,
                "Current report had a syntax error.",
                ImmutableArray<FindingChange>.Empty,
                1, null, 0, null),
            new ComparedFile(
                @"C:\Scripts\missing.ps1",
                ComparedFileStatus.OnlyInBaseline,
                "Absent from current snapshot; deletion cannot be inferred.",
                ImmutableArray<FindingChange>.Empty,
                1, null, 0, null)),
        ImmutableArray.Create(
            "Findings are pattern matches, not proof of execution.",
            "No longer detected does not mean safe."));

    private sealed class TemporaryFolder : IDisposable
    {
        public string Root { get; } = Path.Combine(Path.GetTempPath(),
            "bs-compare-json-" + Guid.NewGuid().ToString("N"));

        public TemporaryFolder() => Directory.CreateDirectory(Root);

        public void Dispose()
        {
            if (Directory.Exists(Root))
            {
                Directory.Delete(Root, recursive: true);
            }
        }
    }
}
