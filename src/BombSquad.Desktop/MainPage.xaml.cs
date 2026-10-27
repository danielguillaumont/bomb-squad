using BombSquad.Analysis;
using BombSquad.Core;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Windows.Storage;
using Windows.Storage.Pickers;
using Windows.Storage.Streams;
using WinRT.Interop;

namespace BombSquad_Desktop;

public sealed partial class MainPage : Page
{
    private readonly AnalysisService _analysisService = new();
    private readonly BatchAnalysisService _batchAnalysisService = new();
    private BatchAnalysisResult? _currentBatch;
    private bool _isAnalyzing;
    private ScriptSourceDocument? _sourceDocument;
    private AnalysisResult? _currentResult;
    private string? _currentSourceIdentifier;

    private sealed record BatchFileOption(int Index, string Label);

    private const string DemoScript = """
        if ($false) {
            Remove-Item -LiteralPath 'demo-cache'
            Set-MpPreference -DisableRealtimeMonitoring $true
            Set-ItemProperty -Path 'HKCU:\Software\BombSquadDemo' -Name Enabled -Value 1
            Add-LocalGroupMember -Group 'Administrators' -Member 'demo-user'
            Register-ScheduledTask -TaskName 'DemoTask' -Action $action
            Invoke-Expression $dynamicSource
        }
        """;

    public MainPage()
    {
        InitializeComponent();
    }

    private async void OpenFile_Click(object sender, RoutedEventArgs e)
    {
        if (_isAnalyzing)
        {
            return;
        }

        try
        {
            Window window = ((App)Application.Current).CurrentWindow
                ?? throw new InvalidOperationException("The application window is not available.");

            var picker = new FileOpenPicker
            {
                SuggestedStartLocation = PickerLocationId.DocumentsLibrary
            };
            picker.FileTypeFilter.Add(".ps1");
            InitializeWithWindow.Initialize(picker, WindowNative.GetWindowHandle(window));

            var selectedFile = await picker.PickSingleFileAsync();
            if (selectedFile is null)
            {
                return;
            }

            ExitBatchMode();
            SetBusy(true);
            ParseStatusText.Text = "Reading and inspecting selected PowerShell file...";

            string selectedPath = selectedFile.Path;
            PowerShellScriptFile input = await Task.Run(
                () => PowerShellScriptFileReader.Read(selectedPath));

            AnalysisResult result = await Task.Run(
                () => _analysisService.Analyze(
                    new AnalysisRequest(input.SourceText, input.FullPath)));

            ShowAnalysis(result, Path.GetFileName(input.FullPath), input.FullPath,
                input.SourceText);
        }
        catch (Exception ex)
        {
            ClearAnalysis();
            SourceNameText.Text = "File could not be inspected";
            ParseStatusText.Text = $"Input error: {ex.Message}";
            DetailsTitleText.Text = "Inspection not completed";
            EvidenceText.Text = "The selected file was not analyzed.";
            LimitationsText.Text =
                "Check that the file exists, is accessible, uses supported text encoding, " +
                "and does not exceed 1 MiB.";
        }
        finally
        {
            SetBusy(false);
        }
    }

    private void RunDemo_Click(object sender, RoutedEventArgs e)
    {
        if (_isAnalyzing)
        {
            return;
        }

        ExitBatchMode();
        SetBusy(true);
        try
        {
            AnalysisResult result = _analysisService.Analyze(
                new AnalysisRequest(DemoScript, "desktop-demo.ps1"));

            ShowAnalysis(result, "desktop-demo.ps1 (built-in sample)",
                "Built-in sample", DemoScript);
        }
        catch (Exception ex)
        {
            ClearAnalysis();
            ParseStatusText.Text = $"Analysis failed: {ex.Message}";
        }
        finally
        {
            SetBusy(false);
        }
    }

    private async void OpenBatch_Click(object sender, RoutedEventArgs e)
    {
        if (_isAnalyzing)
        {
            return;
        }

        try
        {
            Window window = ((App)Application.Current).CurrentWindow
                ?? throw new InvalidOperationException("The application window is not available.");

            var picker = new FileOpenPicker
            {
                SuggestedStartLocation = PickerLocationId.DocumentsLibrary
            };
            picker.FileTypeFilter.Add(".ps1");
            InitializeWithWindow.Initialize(picker, WindowNative.GetWindowHandle(window));

            var selectedFiles = await picker.PickMultipleFilesAsync();
            if (selectedFiles is null || selectedFiles.Count == 0)
            {
                return; // Cancellation preserves the current inspection.
            }

            if (selectedFiles.Count > BatchAnalysisService.MaximumFileCount)
            {
                ParseStatusText.Text =
                    $"Select no more than {BatchAnalysisService.MaximumFileCount} files per batch.";
                return;
            }

            string[] paths = selectedFiles.Select(file => file.Path).ToArray();
            ExitBatchMode();
            SetBusy(true);
            ParseStatusText.Text = $"Inspecting {paths.Length} selected files as text...";

            BatchAnalysisResult batch = await Task.Run(
                () => _batchAnalysisService.AnalyzeFiles(paths));

            _currentBatch = batch;
            BatchSummaryText.Text =
                $"{batch.FileCount} requested · {batch.AnalyzedFileCount} analyzed · " +
                $"{batch.InputErrorCount} input errors · {batch.ParserErrorFileCount} files with syntax errors · " +
                $"{batch.TotalFindingCount} total findings";

            BatchFileSelector.ItemsSource = batch.Files
                .Select((file, index) => new BatchFileOption(index, FormatBatchFileLabel(file, index)))
                .ToArray();
            BatchReviewPanel.Visibility = Visibility.Visible;
            ExportReportButton.Content = "Export batch JSON";
            BatchFileSelector.SelectedIndex = 0;
        }
        catch (Exception ex)
        {
            ExitBatchMode();
            ClearAnalysis();
            SourceNameText.Text = "Batch could not be inspected";
            ParseStatusText.Text = $"Batch input error: {ex.Message}";
            DetailsTitleText.Text = "Batch inspection not completed";
            EvidenceText.Text = "No PowerShell was executed.";
        }
        finally
        {
            SetBusy(false);
        }
    }

    private static string FormatBatchFileLabel(BatchFileAnalysis file, int index)
    {
        string name = Path.GetFileName(file.FullPath ?? file.RequestedPath);
        if (string.IsNullOrWhiteSpace(name)) name = "Unknown file";
        string status = file.InputError is not null
            ? $"Input error: {file.InputError.Code}"
            : file.HasParserErrors
                ? "Syntax errors"
                : $"{file.Result?.Findings.Length ?? 0} findings";
        return $"{index + 1}. {name} — {status}";
    }

    private void BatchFileSelector_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_currentBatch is null || BatchFileSelector.SelectedItem is not BatchFileOption option)
        {
            return;
        }

        BatchFileAnalysis file = _currentBatch.Files[option.Index];
        string path = file.FullPath ?? file.RequestedPath;
        string displayName = Path.GetFileName(path);

        if (file.Result is not null && file.SourceText is not null)
        {
            ShowAnalysis(file.Result, displayName, path, file.SourceText);
        }
        else
        {
            // Input errors are not clean scripts and must never look like successful inspections.
            ClearAnalysis();
            SourceNameText.Text = displayName;
            ToolTipService.SetToolTip(SourceNameText, path);
            CommandCountText.Text = "0";
            FindingCountText.Text = "0";
            DiagnosticCountText.Text = "0";
            DetailsTitleText.Text = "File could not be inspected";
            LocationText.Text = file.InputError?.Code ?? "Source unavailable";
            EvidenceText.Text = file.InputError?.Message ?? "The source snapshot is unavailable.";
            PotentialEffectText.Text = "This file was not analyzed.";
            LimitationsText.Text = "No findings is not a safety verdict. This input could not be inspected.";
            NextStepText.Text = "Correct the input issue and select the file again.";
            ParseStatusText.Text = $"Batch file input error: {LocationText.Text}";
        }

        ExportReportButton.Content = "Export batch JSON";
        ExportReportButton.IsEnabled = !_isAnalyzing;
    }

    private void ExitBatchMode()
    {
        _currentBatch = null;
        BatchFileSelector.SelectedIndex = -1;
        BatchFileSelector.ItemsSource = null;
        BatchReviewPanel.Visibility = Visibility.Collapsed;
        ExportReportButton.Content = "Export report";
    }

    private void SetBusy(bool busy)
    {
        _isAnalyzing = busy;
        OpenComparisonWorkspaceButton.IsEnabled = !busy;
        ComparisonLoadButton.IsEnabled = !busy;
        ComparisonExportButton.IsEnabled = !busy && _currentComparison is not null;
        ComparisonFileSelector.IsEnabled = !busy && _currentComparison is not null;
        ComparisonChangeList.IsEnabled = !busy && _currentComparison is not null;
        OpenFileButton.IsEnabled = !busy;
        OpenBatchButton.IsEnabled = !busy;
        BatchFileSelector.IsEnabled = !busy;
        DemoInspectionButton.IsEnabled = !busy;
        OpenSourceButton.IsEnabled = !busy && _sourceDocument is not null;
        ExportReportButton.IsEnabled = !busy &&
            (_currentResult is not null || _currentBatch is not null);
    }

    private void ClearAnalysis()
    {
        ShowReviewWorkspace();
        _sourceDocument = null;
        _currentResult = null;
        _currentSourceIdentifier = null;
        ExportReportButton.IsEnabled = false;
        ExportStatusText.Text = "";
        ExportStatusText.Visibility = Visibility.Collapsed;
        OpenSourceButton.IsEnabled = false;
        SourceLinesList.SelectedIndex = -1;
        SourceLinesList.ItemsSource = null;
        SourceDocumentNameText.Text = "No script loaded";
        SourceLocationHintText.Text = "Select an inspection record to see its source location.";
        SourceLineStatusText.Text = "Open a file or try the sample to examine original source.";
        JumpToSourceButton.IsEnabled = false;
        FindingsList.SelectedIndex = -1;
        FindingsList.ItemsSource = null;
        FindingsList.Visibility = Visibility.Visible;
        DiagnosticsList.SelectedIndex = -1;
        DiagnosticsList.ItemsSource = null;
        DiagnosticsList.Visibility = Visibility.Collapsed;
        RegisterKickerText.Text = "FINDING REGISTER";
        RegisterTitleText.Text = "Items for review";
        RegisterHintText.Text =
            "Detection rules report potential operations, not confirmed effects.";
        EvidenceLabelText.Text = "Original source";
        CommandCountText.Text = "\u2014";
        FindingCountText.Text = "\u2014";
        DiagnosticCountText.Text = "\u2014";
        SourceNameText.Text = "No source analyzed";
        DetailsTitleText.Text = "Select a finding";
        LocationText.Text = "No evidence selected";
        EvidenceText.Text = "Choose a PowerShell script to inspect its source.";
        PotentialEffectText.Text = "No analysis available.";
        LimitationsText.Text = "Static analysis does not establish runtime effects.";
        NextStepText.Text = "Inspect the source and its context before running it.";
    }

    private void ShowAnalysis(AnalysisResult result, string displayName,
        string sourceLocation, string sourceText)
    {
        ShowReviewWorkspace();
        _currentResult = result;
        _currentSourceIdentifier = sourceLocation == "Built-in sample"
            ? "desktop-demo.ps1" : sourceLocation;
        ExportReportButton.IsEnabled = true;
        ExportStatusText.Text = "";
        ExportStatusText.Visibility = Visibility.Collapsed;
        _sourceDocument = new ScriptSourceDocument(sourceText);
        OpenSourceButton.IsEnabled = true;
        SourceLinesList.SelectedIndex = -1;
        SourceLinesList.ItemsSource = _sourceDocument.Lines.ToArray();
        SourceDocumentNameText.Text = displayName;
        SourceLocationHintText.Text = "Select a finding or diagnostic to locate its source.";
        SourceLineStatusText.Text =
            $"{_sourceDocument.Lines.Length} original lines \u00B7 static view \u00B7 no execution";
        JumpToSourceButton.IsEnabled = false;
        FindingsList.SelectedIndex = -1;
        FindingsList.ItemsSource = null;
        FindingsList.Visibility = Visibility.Visible;
        DiagnosticsList.SelectedIndex = -1;
        DiagnosticsList.ItemsSource = null;
        DiagnosticsList.Visibility = Visibility.Collapsed;
        RegisterKickerText.Text = "FINDING REGISTER";
        RegisterTitleText.Text = "Items for review";
        RegisterHintText.Text =
            "Detection rules report potential operations, not confirmed effects.";
        EvidenceLabelText.Text = "Original source";

        SourceNameText.Text = displayName;
        ToolTipService.SetToolTip(SourceNameText, sourceLocation);
        CommandCountText.Text = result.Commands.Length.ToString();
        FindingCountText.Text = result.Findings.Length.ToString();
        DiagnosticCountText.Text = result.Diagnostics.Length.ToString();
        ParseStatusText.Text =
            $"Status: {result.Status} | Rules skipped: {result.RulesSkipped} | " +
            $"Engine: {result.EngineVersion}";

        FindingsList.ItemsSource = result.Findings.ToArray();

        if (result.RulesSkipped)
        {
            DetailsTitleText.Text = "Analysis incomplete \u2014 syntax errors";
            LocationText.Text = $"{result.Diagnostics.Length} parser diagnostic(s)";
            EvidenceText.Text = string.Join(
                Environment.NewLine,
                result.Diagnostics.Select(diagnostic =>
                    $"{diagnostic.Code}: {diagnostic.Message}"));
            PotentialEffectText.Text = "Detection rules were skipped due to parser errors.";
            LimitationsText.Text =
                "No findings is not a safety verdict. Correct the syntax and inspect again.";
            NextStepText.Text = "Review the parser diagnostics and repair the script syntax.";
            RegisterKickerText.Text = "PARSER DIAGNOSTICS";
            RegisterTitleText.Text = "Syntax issues to review";
            RegisterHintText.Text =
                "Rule evaluation was skipped because PowerShell parsing reported errors.";
            FindingsList.Visibility = Visibility.Collapsed;
            DiagnosticsList.ItemsSource = result.Diagnostics.ToArray();
            DiagnosticsList.Visibility = Visibility.Visible;
            if (result.Diagnostics.Length > 0)
            {
                DiagnosticsList.SelectedIndex = 0;
            }
        }
        else if (result.Findings.Length > 0)
        {
            FindingsList.SelectedIndex = 0;
        }
        else
        {
            DetailsTitleText.Text = "No matching findings";
            LocationText.Text = "No supported rule matches";
            EvidenceText.Text = "No matching source evidence.";
            PotentialEffectText.Text = "The implemented detection rules found no matching operations.";
            LimitationsText.Text =
                "The current rule set is partial. No findings does not establish safety.";
            NextStepText.Text = "Review the script, its inputs, and its execution context.";
        }
    }

    private void FindingsList_SelectionChanged(
        object sender,
        SelectionChangedEventArgs e)
    {
        if (FindingsList.SelectedItem is not Finding finding)
        {
            return;
        }

        DetailsTitleText.Text = $"{finding.RuleId} \u00B7 {finding.Title}";
        LocationText.Text =
            $"{finding.Family} | Line {finding.SourceSpan.StartLine}, " +
            $"Column {finding.SourceSpan.StartColumn} | {finding.Certainty}";
        EvidenceText.Text = finding.Evidence;
        PotentialEffectText.Text = finding.PotentialEffect;
        LimitationsText.Text = string.Join(
            Environment.NewLine,
            finding.Limitations.Select(limitation => $"\u2022 {limitation}"));
        NextStepText.Text = finding.NextStep;

        ScriptSourceLine? selectedLine =
            _sourceDocument?.GetLine(finding.SourceSpan.StartLine);
        if (selectedLine is not null)
        {
            SourceLinesList.SelectedItem = selectedLine;
            JumpToSourceButton.IsEnabled = true;
        }
        else
        {
            SourceLinesList.SelectedIndex = -1;
            JumpToSourceButton.IsEnabled = false;
        }

        UpdateSourceLocationHint();
    }

    private void DiagnosticsList_SelectionChanged(
        object sender,
        SelectionChangedEventArgs e)
    {
        if (DiagnosticsList.SelectedItem is not ParseDiagnostic diagnostic)
        {
            return;
        }

        DetailsTitleText.Text = $"Parser error \u00B7 {diagnostic.Code}";
        LocationText.Text =
            $"Line {diagnostic.SourceSpan.StartLine}, " +
            $"Column {diagnostic.SourceSpan.StartColumn} | Syntax diagnostic";
        EvidenceLabelText.Text = "Parser message";
        EvidenceText.Text = diagnostic.Message;
        PotentialEffectText.Text =
            "This source could not be fully parsed; detection rules were skipped.";
        LimitationsText.Text =
            "A parser error is not a safety verdict. Correct the syntax, " +
            "then inspect the complete script again.";
        NextStepText.Text =
            "Review the highlighted original source line and surrounding context.";

        ScriptSourceLine? selectedLine =
            _sourceDocument?.GetLine(diagnostic.SourceSpan.StartLine);
        if (selectedLine is not null)
        {
            SourceLinesList.SelectedItem = selectedLine;
            JumpToSourceButton.IsEnabled = true;
        }
        else
        {
            SourceLinesList.SelectedIndex = -1;
            JumpToSourceButton.IsEnabled = false;
        }

        UpdateSourceLocationHint();
    }

    private async void ExportReport_Click(object sender, RoutedEventArgs e)
    {
        if (_isAnalyzing || (_currentBatch is null &&
            (_currentResult is null || _currentSourceIdentifier is null)))
        {
            return;
        }

        BatchAnalysisResult? batch = _currentBatch;
        AnalysisResult? result = _currentResult;
        string sourceIdentifier = _currentSourceIdentifier ?? "batch.ps1";
        SetBusy(true);

        try
        {
            Window window = ((App)Application.Current).CurrentWindow
                ?? throw new InvalidOperationException("The application window is not available.");

            var picker = new FileSavePicker
            {
                SuggestedStartLocation = PickerLocationId.DocumentsLibrary,
                SuggestedFileName = batch is null
                    ? Path.GetFileNameWithoutExtension(sourceIdentifier) + "-bomb-squad-report"
                    : "bomb-squad-batch-report"
            };
            picker.FileTypeChoices.Add("JSON report", new List<string> { ".json" });
            InitializeWithWindow.Initialize(picker, WindowNative.GetWindowHandle(window));

            StorageFile? selectedFile = await picker.PickSaveFileAsync();
            if (selectedFile is null)
            {
                return;
            }

            // The native Save dialog asks for confirmation before replacing a file.
            // Nothing from the inspected PowerShell script is executed.
            string report = batch is not null
                ? BatchJsonAnalysisReportWriter.Serialize(batch)
                : JsonAnalysisReportWriter.Serialize(sourceIdentifier, result!);
            await FileIO.WriteTextAsync(
                selectedFile, report + Environment.NewLine, UnicodeEncoding.Utf8);

            ExportStatusText.Text = $"Report saved: {selectedFile.Name}. Report may contain source excerpts and file paths.";
            ExportStatusText.Visibility = Visibility.Visible;
        }
        catch (Exception ex)
        {
            ExportStatusText.Text = $"Report not saved: {ex.Message}";
            ExportStatusText.Visibility = Visibility.Visible;
        }
        finally
        {
            SetBusy(false);
        }
    }

    private void SourceLinesList_SelectionChanged(
        object sender,
        SelectionChangedEventArgs e)
    {
        if (SourceLinesList.SelectedItem is ScriptSourceLine line &&
            _sourceDocument is not null)
        {
            SourceLineStatusText.Text =
                $"Viewing line {line.LineNumber} of {_sourceDocument.Lines.Length} \u00B7 " +
                "original source \u00B7 not executed";
        }

        UpdateSourceLocationHint();
    }

    private void UpdateSourceLocationHint()
    {
        if (SourceLinesList.SelectedItem is not ScriptSourceLine line)
        {
            SourceLocationHintText.Text =
                "Select a finding or diagnostic to locate its source.";
            return;
        }

        if (DiagnosticsList.SelectedItem is ParseDiagnostic diagnostic &&
            diagnostic.SourceSpan.StartLine == line.LineNumber)
        {
            SourceLocationHintText.Text =
                $"Parser diagnostic \u00B7 line {line.LineNumber}, " +
                $"column {diagnostic.SourceSpan.StartColumn}";
        }
        else if (FindingsList.SelectedItem is Finding finding &&
                 finding.SourceSpan.StartLine == line.LineNumber)
        {
            SourceLocationHintText.Text =
                $"Inspection finding \u00B7 line {line.LineNumber}, " +
                $"column {finding.SourceSpan.StartColumn}";
        }
        else
        {
            SourceLocationHintText.Text =
                $"Browsing original source \u00B7 line {line.LineNumber}";
        }
    }

    private void JumpToSource_Click(object sender, RoutedEventArgs e)
    {
        if (SourceLinesList.SelectedItem is ScriptSourceLine)
        {
            ShowSourceWorkspace();
        }
    }

    private void OpenSource_Click(object sender, RoutedEventArgs e)
    {
        if (_sourceDocument is null)
        {
            return;
        }

        if (SourceLinesList.SelectedItem is null && _sourceDocument.Lines.Length > 0)
        {
            SourceLinesList.SelectedItem = _sourceDocument.Lines[0];
        }

        ShowSourceWorkspace();
    }

    private void BackToReview_Click(object sender, RoutedEventArgs e)
    {
        ShowReviewWorkspace();
    }

    private void ShowReviewWorkspace()
    {
        ComparisonWorkspaceScrollViewer.Visibility = Visibility.Collapsed;
        SourceExplorerSection.Visibility = Visibility.Collapsed;
        ReviewWorkspaceScrollViewer.Visibility = Visibility.Visible;
    }

    private void ShowSourceWorkspace()
    {
        if (_sourceDocument is null)
        {
            return;
        }

        ComparisonWorkspaceScrollViewer.Visibility = Visibility.Collapsed;
        ReviewWorkspaceScrollViewer.Visibility = Visibility.Collapsed;
        SourceExplorerSection.Visibility = Visibility.Visible;

        DispatcherQueue.TryEnqueue(() =>
        {
            if (SourceExplorerSection.Visibility != Visibility.Visible)
            {
                return;
            }

            SourceLinesList.UpdateLayout();
            if (SourceLinesList.SelectedItem is ScriptSourceLine selectedLine)
            {
                SourceLinesList.ScrollIntoView(
                    selectedLine, ScrollIntoViewAlignment.Leading);
            }

            SourceLinesList.Focus(FocusState.Programmatic);
        });
    }
}
