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
    private bool _isAnalyzing;
    private ScriptSourceDocument? _sourceDocument;
    private AnalysisResult? _currentResult;
    private string? _currentSourceIdentifier;

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

    private void SetBusy(bool busy)
    {
        _isAnalyzing = busy;
        OpenFileButton.IsEnabled = !busy;
        DemoInspectionButton.IsEnabled = !busy;
        OpenSourceButton.IsEnabled = !busy && _sourceDocument is not null;
        ExportReportButton.IsEnabled = !busy && _currentResult is not null;
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
    }

    private async void ExportReport_Click(object sender, RoutedEventArgs e)
    {
        if (_isAnalyzing || _currentResult is null || _currentSourceIdentifier is null)
        {
            return;
        }

        AnalysisResult result = _currentResult;
        string sourceIdentifier = _currentSourceIdentifier;
        SetBusy(true);

        try
        {
            Window window = ((App)Application.Current).CurrentWindow
                ?? throw new InvalidOperationException("The application window is not available.");

            var picker = new FileSavePicker
            {
                SuggestedStartLocation = PickerLocationId.DocumentsLibrary,
                SuggestedFileName = Path.GetFileNameWithoutExtension(sourceIdentifier)
                    + "-bomb-squad-report"
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
            string report = JsonAnalysisReportWriter.Serialize(sourceIdentifier, result);
            await FileIO.WriteTextAsync(
                selectedFile, report + Environment.NewLine, UnicodeEncoding.Utf8);

            ExportStatusText.Text = $"Report saved: {selectedFile.Name}. Report may contain source excerpts.";
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
        SourceExplorerSection.Visibility = Visibility.Collapsed;
        ReviewWorkspaceScrollViewer.Visibility = Visibility.Visible;
    }

    private void ShowSourceWorkspace()
    {
        if (_sourceDocument is null)
        {
            return;
        }

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
