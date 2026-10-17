using System.Collections.Immutable;
using System.Text.Json;
using System.Text.Json.Serialization;
using BombSquad.Core;

namespace BombSquad.Tests;

public class CoreContractsTests
{
    [Fact]
    public void SourceSpan_UsesExclusiveEndOffset()
    {
        var span = new SourceSpan(
            10, 25,
            2, 1,
            2, 16
        );

        Assert.Equal(15, span.Length);
        Assert.Equal(2, span.StartLine);
        Assert.Equal(25, span.EndOffset);
    }

    [Fact]
    public void AnalysisRequest_PreservesSourceText()
    {
        const string source =
            "Remove-Item .\\demo-cache -Recurse";

        var request = new AnalysisRequest(
            source,
            "sample.ps1"
        );

        Assert.Equal(source, request.SourceText);
        Assert.Equal("sample.ps1", request.SourceName);
    }

    [Fact]
    public void NotImplementedResult_HasExplicitStatus()
    {
        var result = new AnalysisResult(
            AnalysisStatus.NotImplemented,
            ImmutableArray<Finding>.Empty,
            ImmutableArray<ParseDiagnostic>.Empty,
            ImmutableArray<string>.Empty,
            ImmutableArray.Create(
                "No analysis rules have been implemented."
            ),
            "0.0.0",
            "none",
            true
        );

        var options = new JsonSerializerOptions();
        options.Converters.Add(
            new JsonStringEnumConverter()
        );

        string json = JsonSerializer.Serialize(
            result,
            options
        );

        Assert.Contains(
            "\"Status\":\"NotImplemented\"",
            json
        );

        Assert.Contains(
            "\"RulesSkipped\":true",
            json
        );

        Assert.DoesNotContain(
            "\"Status\":\"Safe\"",
            json
        );

        var restored =
            JsonSerializer.Deserialize<AnalysisResult>(
                json,
                options
            );

        Assert.NotNull(restored);
        Assert.Equal(
            AnalysisStatus.NotImplemented,
            restored.Status
        );

        Assert.True(restored.RulesSkipped);
        Assert.Empty(restored.Findings);
    }
}
