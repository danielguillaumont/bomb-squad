using BombSquad.Analysis;

namespace BombSquad.Tests;

public sealed class ScriptSourceDocumentTests
{
    [Fact]
    public void EmptySource_HasOneEmptyLine()
    {
        var document = new ScriptSourceDocument("");
        ScriptSourceLine line = Assert.Single(document.Lines);
        Assert.Equal(1, line.LineNumber);
        Assert.Equal("", line.Text);
        Assert.Equal(0, line.StartOffset);
        Assert.Equal(0, line.EndOffset);
    }

    [Fact]
    public void OneLineWithoutNewline_RetainsExactText()
    {
        const string source = "Get-Date";
        var document = new ScriptSourceDocument(source);
        Assert.Equal(source, document.SourceText);
        Assert.Equal("Get-Date", Assert.Single(document.Lines).Text);
    }

    [Theory]
    [InlineData("one\ntwo", 4)]
    [InlineData("one\rtwo", 4)]
    [InlineData("one\r\ntwo", 5)]
    public void MixedNewlineStyles_PreserveOffsets(string source, int secondStart)
    {
        var document = new ScriptSourceDocument(source);
        Assert.Equal(2, document.Lines.Length);
        Assert.Equal("one", document.Lines[0].Text);
        Assert.Equal(0, document.Lines[0].StartOffset);
        Assert.Equal(3, document.Lines[0].EndOffset);
        Assert.Equal("two", document.Lines[1].Text);
        Assert.Equal(secondStart, document.Lines[1].StartOffset);
        Assert.Equal(source.Length, document.Lines[1].EndOffset);
    }

    [Fact]
    public void TrailingNewline_ProducesFinalEmptyLine()
    {
        var document = new ScriptSourceDocument("Get-Date\r\n");
        Assert.Equal(2, document.Lines.Length);
        Assert.Equal("", document.Lines[1].Text);
        Assert.Equal(10, document.Lines[1].StartOffset);
    }

    [Fact]
    public void MultipleEmptyLines_AreNotDiscarded()
    {
        var document = new ScriptSourceDocument("alpha\n\nbeta\n");
        Assert.Equal(new[] { "alpha", "", "beta", "" },
            document.Lines.Select(line => line.Text));
    }

    [Fact]
    public void Context_IsBoundedAtDocumentEdges()
    {
        var document = new ScriptSourceDocument("first\nsecond\nthird\nfourth\nfifth");
        Assert.Equal(new[] { 1, 2, 3 },
            document.GetContext(1, 2).Select(line => line.LineNumber));
        Assert.Equal(new[] { 3, 4, 5 },
            document.GetContext(5, 2).Select(line => line.LineNumber));
    }

    [Fact]
    public void InvalidLineNumber_ReturnsNoSourceContext()
    {
        var document = new ScriptSourceDocument("Get-Date");
        Assert.Null(document.GetLine(0));
        Assert.Null(document.GetLine(2));
        Assert.Empty(document.GetContext(0));
        Assert.Empty(document.GetContext(2));
    }

    [Fact]
    public void NegativeRadius_IsRejected()
    {
        var document = new ScriptSourceDocument("Get-Date");
        Assert.Throws<ArgumentOutOfRangeException>(() => document.GetContext(1, -1));
    }

    [Fact]
    public void UnicodeSource_IsRetainedWithoutNormalization()
    {
        const string source = "# 🍂\r\nRemove-Item 'demo'";
        var document = new ScriptSourceDocument(source);
        Assert.Equal(source, document.SourceText);
        Assert.Equal(source.IndexOf("Remove-Item", StringComparison.Ordinal),
            document.GetLine(2)!.StartOffset);
        Assert.Equal("0002", document.GetLine(2)!.LineNumberDisplay);
    }

    [Fact]
    public void DocumentConstruction_DoesNotExecuteSource()
    {
        string marker = Path.Combine(Path.GetTempPath(), $"bombsquad-no-exec-{Guid.NewGuid():N}");
        string source = $"New-Item -LiteralPath '{marker}' -ItemType File";
        _ = new ScriptSourceDocument(source);
        Assert.False(File.Exists(marker));
    }
}
