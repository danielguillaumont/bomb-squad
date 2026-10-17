using System.Text.Json;
using BombSquad.Analysis;
using BombSquad.Core;

namespace BombSquad.Tests;

public sealed class JsonAnalysisReportWriterTests
{
    private static AnalysisResult Analyze(string source) =>
        new AnalysisService().Analyze(new AnalysisRequest(source, "inspection.ps1"));

    [Fact]
    public void Serialize_UsesExistingSchemaAndStaticDisclosure()
    {
        AnalysisResult result = Analyze("Invoke-Expression $source");
        using JsonDocument document = JsonDocument.Parse(
            JsonAnalysisReportWriter.Serialize("inspection.ps1", result));
        JsonElement root = document.RootElement;

        Assert.Equal("0.1.0", root.GetProperty("schemaVersion").GetString());
        Assert.Equal("inspection.ps1", root.GetProperty("sourceFile").GetString());
        Assert.Equal(result.EngineVersion, root.GetProperty("engineVersion").GetString());
        Assert.Equal(result.RuleSetVersion, root.GetProperty("ruleSetVersion").GetString());
        Assert.Equal("Parsed", root.GetProperty("status").GetString());
        Assert.False(root.GetProperty("rulesSkipped").GetBoolean());
        Assert.False(root.GetProperty("sourceExecuted").GetBoolean());
        Assert.Equal(1, root.GetProperty("findingCount").GetInt32());
        Assert.Equal(1, root.GetProperty("commandCount").GetInt32());
        Assert.Equal("BS-DE-001", root.GetProperty("findings")[0].GetProperty("ruleId").GetString());
        Assert.True(root.GetProperty("findings")[0].GetProperty("limitations").GetArrayLength() > 0);
        Assert.True(root.GetProperty("findings")[0].GetProperty("sourceSpan").GetProperty("startLine").GetInt32() > 0);
        Assert.Equal(JsonValueKind.Array, root.GetProperty("unresolvedConstructs").ValueKind);
    }

    [Fact]
    public void Serialize_MalformedSourcePreservesDiagnosticsAndSkipping()
    {
        AnalysisResult result = Analyze("Write-Output 'unterminated");
        using JsonDocument document = JsonDocument.Parse(
            JsonAnalysisReportWriter.Serialize("malformed.ps1", result));
        JsonElement root = document.RootElement;

        Assert.Equal("ParsedWithErrors", root.GetProperty("status").GetString());
        Assert.True(root.GetProperty("rulesSkipped").GetBoolean());
        Assert.Equal(0, root.GetProperty("findingCount").GetInt32());
        Assert.True(root.GetProperty("diagnosticCount").GetInt32() > 0);
        Assert.True(root.GetProperty("diagnostics").GetArrayLength() > 0);
        Assert.False(root.GetProperty("sourceExecuted").GetBoolean());
    }

    [Fact]
    public void Serialize_NoFindingDoesNotClaimSafety()
    {
        AnalysisResult result = Analyze("Get-Date");
        using JsonDocument document = JsonDocument.Parse(
            JsonAnalysisReportWriter.Serialize("read-only.ps1", result));
        JsonElement root = document.RootElement;
        Assert.Equal(0, root.GetProperty("findingCount").GetInt32());
        Assert.False(root.GetProperty("sourceExecuted").GetBoolean());
        Assert.Contains(
            root.GetProperty("limitations").EnumerateArray().Select(x => x.GetString()),
            limitation => limitation is not null &&
                          limitation.Contains("absence of findings does not establish safety",
                              StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Serialize_NeverExecutesInspectedPowerShell()
    {
        string marker = Path.Combine(Path.GetTempPath(), $"bs-json-{Guid.NewGuid():N}.txt");
        string source = $"Set-Content -LiteralPath '{marker.Replace("'", "''")}' -Value executed";
        AnalysisResult result = Analyze(source);
        _ = JsonAnalysisReportWriter.Serialize("untrusted.ps1", result);
        Assert.False(File.Exists(marker));
    }

    [Fact]
    public void WriteNew_RejectsExistingReportWithoutOverwriting()
    {
        string path = Path.Combine(Path.GetTempPath(), $"bs-export-{Guid.NewGuid():N}.json");
        try
        {
            File.WriteAllText(path, "DO NOT OVERWRITE");
            Assert.Throws<IOException>(() =>
                JsonAnalysisReportWriter.WriteNew(path, "inspection.ps1", Analyze("Get-Date")));
            Assert.Equal("DO NOT OVERWRITE", File.ReadAllText(path));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void WriteNew_RejectsNonJsonExtension()
    {
        string path = Path.Combine(Path.GetTempPath(), $"bs-export-{Guid.NewGuid():N}.txt");
        Assert.Throws<ArgumentException>(() =>
            JsonAnalysisReportWriter.WriteNew(path, "inspection.ps1", Analyze("Get-Date")));
        Assert.False(File.Exists(path));
    }

    [Fact]
    public void WriteNew_ProducesUtf8JsonWithoutBom()
    {
        string path = Path.Combine(Path.GetTempPath(), $"bs-export-{Guid.NewGuid():N}.json");
        try
        {
            string returned = JsonAnalysisReportWriter.WriteNew(
                path, "inspection.ps1", Analyze("Get-Date"));
            Assert.Equal(Path.GetFullPath(path), returned);
            byte[] bytes = File.ReadAllBytes(path);
            Assert.NotEmpty(bytes);
            Assert.Equal((byte)'{', bytes[0]);
            using JsonDocument document = JsonDocument.Parse(bytes);
            Assert.Equal("inspection.ps1", document.RootElement.GetProperty("sourceFile").GetString());
        }
        finally
        {
            File.Delete(path);
        }
    }
}
