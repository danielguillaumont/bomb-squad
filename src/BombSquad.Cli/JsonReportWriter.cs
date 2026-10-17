using BombSquad.Analysis;
using BombSquad.Core;

// Keep the original CLI entry point and its existing tests.
// Serialization and file creation are shared with the desktop application.
internal static class JsonReportWriter
{
    public static string Write(string reportPath, string sourceFile, AnalysisResult result)
        => JsonAnalysisReportWriter.WriteNew(reportPath, sourceFile, result);
}
