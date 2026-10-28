using System.Text;
using BombSquad.Analysis;
using BombSquad.Core;

namespace BombSquad.Tests;

public sealed class PastedPowerShellInputTests
{
    [Fact]
    public void Validate_PreservesWhitespaceNewlinesAndSourceOffsets()
    {
        const string source = "  Get-Date\r\n  Remove-Item -LiteralPath 'demo-cache'\r\n";
        string validated = PastedPowerShellInput.Validate(source);
        Assert.Same(source, validated);

        AnalysisResult result = new AnalysisService().Analyze(
            new AnalysisRequest(validated, PastedPowerShellInput.SourceIdentifier));

        Assert.Equal(AnalysisStatus.Parsed, result.Status);
        Finding finding = Assert.Single(result.Findings);
        Assert.Equal("BS-FS-001", finding.RuleId);
        Assert.Equal(2, finding.SourceSpan.StartLine);
        Assert.Equal(3, finding.SourceSpan.StartColumn);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("  \t\r\n")]
    public void Validate_RejectsBlankSource(string? source)
    {
        Assert.Throws<ArgumentException>(() => PastedPowerShellInput.Validate(source));
    }

    [Fact]
    public void Validate_AcceptsExactlyOneMiBOfUtf8()
    {
        string source = new('a', PastedPowerShellInput.MaximumSourceSizeBytes);
        Assert.Same(source, PastedPowerShellInput.Validate(source));
    }

    [Fact]
    public void Validate_RejectsAsciiOverOneMiB()
    {
        string source = new('a', PastedPowerShellInput.MaximumSourceSizeBytes + 1);
        Assert.Throws<ArgumentException>(() => PastedPowerShellInput.Validate(source));
    }

    [Fact]
    public void Validate_RejectsMultibyteInputOverByteLimit()
    {
        string source = new('é', PastedPowerShellInput.MaximumSourceSizeBytes / 2 + 1);
        Assert.True(source.Length < PastedPowerShellInput.MaximumSourceSizeBytes);
        Assert.Throws<ArgumentException>(() => PastedPowerShellInput.Validate(source));
    }

    [Fact]
    public void Validate_RejectsEmbeddedNulAndInvalidSurrogates()
    {
        Assert.Throws<ArgumentException>(
            () => PastedPowerShellInput.Validate("Get-Date\0Remove-Item"));
        Assert.Throws<EncoderFallbackException>(
            () => PastedPowerShellInput.Validate("Write-Output '\uD800'"));
    }

    [Fact]
    public void PastedSource_MalformedSyntaxReturnsDiagnosticsWithoutFindings()
    {
        const string source = "Remove-Item -Path 'demo-cache'\nWrite-Output 'unterminated";
        AnalysisResult result = new AnalysisService().Analyze(
            new AnalysisRequest(PastedPowerShellInput.Validate(source),
                PastedPowerShellInput.SourceIdentifier));

        Assert.Equal(AnalysisStatus.ParsedWithErrors, result.Status);
        Assert.True(result.RulesSkipped);
        Assert.NotEmpty(result.Diagnostics);
        Assert.Empty(result.Findings);
    }

    [Fact]
    public void PastedSource_AnalyzedAsDataNeverRunsCommands()
    {
        string marker = Path.Combine(Path.GetTempPath(),
            $"bomb-squad-paste-{Guid.NewGuid():N}.txt");
        string escaped = marker.Replace("'", "''", StringComparison.Ordinal);
        string source = $"Set-Content -LiteralPath '{escaped}' -Value 'executed'";

        AnalysisResult result = new AnalysisService().Analyze(
            new AnalysisRequest(PastedPowerShellInput.Validate(source),
                PastedPowerShellInput.SourceIdentifier));

        Assert.Equal(AnalysisStatus.Parsed, result.Status);
        Assert.Single(result.Commands);
        Assert.False(File.Exists(marker));
    }
}
