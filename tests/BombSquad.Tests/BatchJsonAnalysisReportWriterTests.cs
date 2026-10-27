using System.Text.Json;
using BombSquad.Analysis;

namespace BombSquad.Tests;

public sealed class BatchJsonAnalysisReportWriterTests
{
    [Fact]
    public void Serialize_PreservesNestedSingleFileSchemaAndSafetyDisclosure()
    {
        using var folder = new TemporaryFolder();
        string path = folder.Write("example.ps1", "Invoke-Expression $source");
        BatchAnalysisResult batch = new BatchAnalysisService().AnalyzeFiles(new[] { path });

        using JsonDocument document = JsonDocument.Parse(
            BatchJsonAnalysisReportWriter.Serialize(batch));
        JsonElement root = document.RootElement;

        Assert.Equal("0.1.0", root.GetProperty("schemaVersion").GetString());
        Assert.Equal("batch", root.GetProperty("reportType").GetString());
        Assert.Equal(1, root.GetProperty("fileCount").GetInt32());
        Assert.Equal(1, root.GetProperty("analyzedFileCount").GetInt32());
        Assert.Equal(1, root.GetProperty("totalFindingCount").GetInt32());
        Assert.True(root.GetProperty("allFilesAnalyzed").GetBoolean());
        Assert.False(root.GetProperty("sourceExecuted").GetBoolean());

        JsonElement entry = root.GetProperty("files")[0];
        Assert.Equal("Parsed", entry.GetProperty("outcome").GetString());
        Assert.Equal(JsonValueKind.Null, entry.GetProperty("inputError").ValueKind);
        Assert.Equal(path, entry.GetProperty("fullPath").GetString());
        JsonElement analysis = entry.GetProperty("analysis");
        Assert.Equal("0.1.0", analysis.GetProperty("schemaVersion").GetString());
        Assert.Equal(path, analysis.GetProperty("sourceFile").GetString());
        Assert.Equal("BS-DE-001",
            analysis.GetProperty("findings")[0].GetProperty("ruleId").GetString());
        Assert.False(analysis.GetProperty("sourceExecuted").GetBoolean());
    }

    [Fact]
    public void Serialize_SeparatesInputFailuresAndParserErrors()
    {
        using var folder = new TemporaryFolder();
        string malformed = folder.Write("bad.ps1", "Write-Output 'unterminated");
        string missing = Path.Combine(folder.Root, "missing.ps1");
        BatchAnalysisResult batch = new BatchAnalysisService()
            .AnalyzeFiles(new[] { malformed, missing });

        using JsonDocument document = JsonDocument.Parse(
            BatchJsonAnalysisReportWriter.Serialize(batch));
        JsonElement root = document.RootElement;
        Assert.False(root.GetProperty("allFilesAnalyzed").GetBoolean());
        Assert.Equal(1, root.GetProperty("parserErrorFileCount").GetInt32());
        Assert.Equal(1, root.GetProperty("inputErrorCount").GetInt32());

        JsonElement parseEntry = root.GetProperty("files")[0];
        Assert.Equal("ParsedWithErrors", parseEntry.GetProperty("outcome").GetString());
        Assert.True(parseEntry.GetProperty("analysis").GetProperty("rulesSkipped").GetBoolean());
        Assert.Equal(JsonValueKind.Null, parseEntry.GetProperty("inputError").ValueKind);

        JsonElement errorEntry = root.GetProperty("files")[1];
        Assert.Equal("InputError", errorEntry.GetProperty("outcome").GetString());
        Assert.Equal("FileNotFound",
            errorEntry.GetProperty("inputError").GetProperty("code").GetString());
        Assert.Equal(JsonValueKind.Null, errorEntry.GetProperty("analysis").ValueKind);
        Assert.False(root.GetProperty("sourceExecuted").GetBoolean());
    }

    [Fact]
    public void WriteNew_RejectsOverwriteAndPreservesExistingContents()
    {
        using var folder = new TemporaryFolder();
        string script = folder.Write("script.ps1", "Get-Date");
        BatchAnalysisResult batch = new BatchAnalysisService().AnalyzeFiles(new[] { script });
        string output = folder.Write("existing.json", "DO NOT OVERWRITE");

        Assert.Throws<IOException>(() =>
            BatchJsonAnalysisReportWriter.WriteNew(output, batch));
        Assert.Equal("DO NOT OVERWRITE", File.ReadAllText(output));
    }

    [Fact]
    public void WriteNew_RejectsOtherExtensions()
    {
        using var folder = new TemporaryFolder();
        string script = folder.Write("script.ps1", "Get-Date");
        BatchAnalysisResult batch = new BatchAnalysisService().AnalyzeFiles(new[] { script });
        string output = Path.Combine(folder.Root, "report.txt");

        Assert.Throws<ArgumentException>(() =>
            BatchJsonAnalysisReportWriter.WriteNew(output, batch));
        Assert.False(File.Exists(output));
    }

    [Fact]
    public void WriteNew_ProducesUtf8JsonWithoutBom()
    {
        using var folder = new TemporaryFolder();
        string script = folder.Write("script.ps1", "Get-Date");
        BatchAnalysisResult batch = new BatchAnalysisService().AnalyzeFiles(new[] { script });
        string output = Path.Combine(folder.Root, "report.json");

        string saved = BatchJsonAnalysisReportWriter.WriteNew(output, batch);

        Assert.Equal(Path.GetFullPath(output), saved);
        byte[] bytes = File.ReadAllBytes(output);
        Assert.NotEmpty(bytes);
        Assert.Equal((byte)'{', bytes[0]);
        using JsonDocument document = JsonDocument.Parse(bytes);
        Assert.Equal("batch", document.RootElement.GetProperty("reportType").GetString());
    }

    private sealed class TemporaryFolder : IDisposable
    {
        public string Root { get; } = Path.Combine(
            Path.GetTempPath(), "bs-batch-json-" + Guid.NewGuid().ToString("N"));

        public TemporaryFolder() => Directory.CreateDirectory(Root);

        public string Write(string name, string text)
        {
            string path = Path.Combine(Root, name);
            File.WriteAllText(path, text, System.Text.Encoding.UTF8);
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
