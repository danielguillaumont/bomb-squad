using BombSquad.Analysis;
using BombSquad.Core;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Windows.Storage.Pickers;
using WinRT.Interop;

namespace BombSquad_Desktop;

public sealed partial class MainPage : Page
{
    private readonly AnalysisService _analysisService = new();
    private bool _isAnalyzing;
    private ScriptSourceDocument? _sourceDocument;

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
    }

    private void ClearAnalysis()
    {
        _sourceDocument = null;
        SourceLinesList.SelectedIndex = -1;
        SourceLinesList.ItemsSource = null;
        SourceDocumentNameText.Text = "No script loaded";
        SourceLineStatusText.Text = "Open a file or try the sample to examine original source.";
        JumpToSourceButton.IsEnabled = false;
        FindingsList.SelectedIndex = -1;
        FindingsList.ItemsSource = null;
        CommandCountText.Text = "â€”";
        FindingCountText.Text = "â€”";
        DiagnosticCountText.Text = "â€”";
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
        _sourceDocument = new ScriptSourceDocument(sourceText);
        SourceLinesList.SelectedIndex = -1;
        SourceLinesList.ItemsSource = _sourceDocument.Lines.ToArray();
        SourceDocumentNameText.Text = displayName;
        SourceLineStatusText.Text =
            $"{_sourceDocument.Lines.Length} original lines Â· static view Â· no execution";
        JumpToSourceButton.IsEnabled = false;
        FindingsList.SelectedIndex = -1;
        FindingsList.ItemsSource = null;

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
            DetailsTitleText.Text = "Analysis incomplete â€” syntax errors";
            LocationText.Text = $"{result.Diagnostics.Length} parser diagnostic(s)";
            EvidenceText.Text = string.Join(
                Environment.NewLine,
                result.Diagnostics.Select(diagnostic =>
                    $"{diagnostic.Code}: {diagnostic.Message}"));
            PotentialEffectText.Text = "Detection rules were skipped due to parser errors.";
            LimitationsText.Text =
                "No findings is not a safety verdict. Correct the syntax and inspect again.";
            NextStepText.Text = "Review the parser diagnostics and repair the script syntax.";
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

        DetailsTitleText.Text = $"{finding.RuleId} Â· {finding.Title}";
        LocationText.Text =
            $"{finding.Family} | Line {finding.SourceSpan.StartLine}, " +
            $"Column {finding.SourceSpan.StartColumn} | {finding.Certainty}";
        EvidenceText.Text = finding.Evidence;
        PotentialEffectText.Text = finding.PotentialEffect;
        LimitationsText.Text = string.Join(
            Environment.NewLine,
            finding.Limitations.Select(limitation => $"â€¢ {limitation}"));
        NextStepText.Text = finding.NextStep;

        ScriptSourceLine? selectedLine =
            _sourceDocument?.GetLine(finding.SourceSpan.StartLine);
        if (selectedLine is not null)
        {
            SourceLinesList.SelectedItem = selectedLine;
            JumpToSourceButton.IsEnabled = true;
            DispatcherQueue.TryEnqueue(() =>
            {
                if (ReferenceEquals(SourceLinesList.SelectedItem, selectedLine))
                {
                    SourceLinesList.UpdateLayout();
                    SourceLinesList.ScrollIntoView(
                        selectedLine, ScrollIntoViewAlignment.Leading);
                }
            });
        }
        else
        {
            SourceLinesList.SelectedIndex = -1;
            JumpToSourceButton.IsEnabled = false;
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
                $"Viewing line {line.LineNumber} of {_sourceDocument.Lines.Length} Â· " +
                "original source Â· not executed";
        }
    }

    private void JumpToSource_Click(object sender, RoutedEventArgs e)
    {
        if (SourceLinesList.SelectedItem is not ScriptSourceLine line)
        {
            return;
        }

        SourceExplorerSection.StartBringIntoView();

        DispatcherQueue.TryEnqueue(() =>
        {
            if (!ReferenceEquals(SourceLinesList.SelectedItem, line))
            {
                return;
            }

            SourceLinesList.UpdateLayout();
            SourceLinesList.ScrollIntoView(
                line, ScrollIntoViewAlignment.Leading);
            SourceLinesList.Focus(FocusState.Programmatic);
        });
    }
}
