using System.Text;
using BombSquad.Analysis;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Windows.Storage;
using Windows.Storage.Pickers;
using Windows.Storage.Streams;
using WinRT.Interop;

namespace BombSquad_Desktop;

/// <summary>
/// Desktop comparison only reads two explicitly selected JSON reports.
/// It never opens, parses, or executes any referenced PowerShell script.
/// </summary>
public sealed partial class MainPage
{
    private BatchReportComparison? _currentComparison;
    private string? _baselineComparisonPath;
    private string? _currentComparisonPath;
    private string? _inspectionStatusBeforeComparison;

    private sealed record ComparisonFileOption(int Index, string Label);
    private sealed record ComparisonChangeOption(
        FindingChange Change, string Label, string Description);

    private void OpenComparisonWorkspace_Click(object sender, RoutedEventArgs e)
    {
        if (_isAnalyzing) return;

        _inspectionStatusBeforeComparison = ParseStatusText.Text;
        ReviewWorkspaceScrollViewer.Visibility = Visibility.Collapsed;
        SourceExplorerSection.Visibility = Visibility.Collapsed;
        ComparisonWorkspaceScrollViewer.Visibility = Visibility.Visible;
        ParseStatusText.Text = _currentComparison is null
            ? "Comparison mode | Select two batch JSON reports | No PowerShell executed"
            : "Comparison mode | Loaded two report snapshots | No PowerShell executed";
    }

    private void ComparisonBack_Click(object sender, RoutedEventArgs e)
    {
        if (_isAnalyzing) return;
        ShowReviewWorkspace();
        if (_inspectionStatusBeforeComparison is not null)
        {
            ParseStatusText.Text = _inspectionStatusBeforeComparison;
            _inspectionStatusBeforeComparison = null;
        }
    }

    private static async Task<string> ReadComparisonReportAsync(string path)
    {
        // A bounded JSON snapshot, not an instruction to read its sourcePath fields.
        const long maximumBytes = 32L * 1024 * 1024;
        return await Task.Run(() =>
        {
            if (!string.Equals(Path.GetExtension(path), ".json",
                    StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException("Choose a .json batch report.");
            }

            var info = new FileInfo(path);
            if (info.Length > maximumBytes)
            {
                throw new InvalidOperationException("JSON report exceeds the 32 MiB desktop limit.");
            }

            string json = File.ReadAllText(path, new UTF8Encoding(false, true));
            if (json.Length > BatchReportComparisonService.MaximumReportCharacters)
            {
                throw new InvalidOperationException("JSON report exceeds the comparison limit.");
            }
            return json;
        });
    }

    private static async Task<StorageFile?> PickBatchReportAsync(Window window)
    {
        var picker = new FileOpenPicker
        {
            SuggestedStartLocation = PickerLocationId.DocumentsLibrary
        };
        picker.FileTypeFilter.Add(".json");
        InitializeWithWindow.Initialize(picker, WindowNative.GetWindowHandle(window));
        return await picker.PickSingleFileAsync();
    }

    private async void ComparisonLoad_Click(object sender, RoutedEventArgs e)
    {
        if (_isAnalyzing) return;

        try
        {
            Window window = ((App)Application.Current).CurrentWindow
                ?? throw new InvalidOperationException("The application window is not available.");

            // Cancellation at either picker leaves the previously loaded comparison intact.
            ComparisonStatusText.Text = "Choose the baseline (older) batch JSON report.";
            StorageFile? baselineFile = await PickBatchReportAsync(window);
            if (baselineFile is null)
            {
                ComparisonStatusText.Text = "Selection cancelled. Previous comparison retained.";
                return;
            }

            ComparisonStatusText.Text = "Choose the current (newer) batch JSON report.";
            StorageFile? currentFile = await PickBatchReportAsync(window);
            if (currentFile is null)
            {
                ComparisonStatusText.Text = "Selection cancelled. Previous comparison retained.";
                return;
            }

            if (string.Equals(baselineFile.Path, currentFile.Path,
                    StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException("Choose two different saved reports.");
            }

            SetBusy(true);
            ComparisonStatusText.Text = "Validating and comparing the two saved reports...";
            string oldJson = await ReadComparisonReportAsync(baselineFile.Path);
            string newJson = await ReadComparisonReportAsync(currentFile.Path);
            BatchReportComparison comparison = await Task.Run(
                () => new BatchReportComparisonService().Compare(oldJson, newJson));

            _currentComparison = comparison;
            _baselineComparisonPath = baselineFile.Path;
            _currentComparisonPath = currentFile.Path;
            RenderComparison();
            ParseStatusText.Text = "Comparison complete | JSON snapshots only | No PowerShell executed";
        }
        catch (Exception ex)
        {
            ComparisonStatusText.Text = $"Comparison not completed: {ex.Message}";
            ParseStatusText.Text = "Comparison input error | Previous comparison retained | No PowerShell executed";
        }
        finally
        {
            SetBusy(false);
        }
    }

    private static string FileLabel(ComparedFile file, int index)
    {
        string name = Path.GetFileName(file.FilePath);
        if (string.IsNullOrWhiteSpace(name)) name = file.FilePath;
        return $"{index + 1}. {name} — {file.Status}";
    }

    private void RenderComparison()
    {
        if (_currentComparison is not BatchReportComparison comparison) return;

        ComparisonBaselinePathText.Text = $"Baseline: {_baselineComparisonPath}";
        ComparisonCurrentPathText.Text = $"Current: {_currentComparisonPath}";
        ComparisonMetricsText.Text =
            $"+ {comparison.NewlyDetectedCount} newly detected    " +
            $"= {comparison.StillDetectedCount} still detected    " +
            $"- {comparison.NoLongerDetectedCount} no longer detected";
        ComparisonCoverageText.Text =
            $"{comparison.ComparedFileCount} compared · " +
            $"{comparison.IndeterminateFileCount} indeterminate · " +
            $"{comparison.OnlyInBaselineCount} baseline only · " +
            $"{comparison.OnlyInCurrentCount} current only";
        ComparisonStatusText.Text = comparison.IndeterminateFileCount > 0 ||
            comparison.OnlyInBaselineCount > 0 || comparison.OnlyInCurrentCount > 0
            ? "Comparison has incomplete or unmatched file coverage. Review each file status."
            : "Compared matching file identities using rule ID and exact evidence text.";
        ComparisonLimitationsText.Text = string.Join(Environment.NewLine,
            comparison.Limitations.Select(limitation => $"• {limitation}"));

        ComparisonFileSelector.SelectedIndex = -1;
        ComparisonFileSelector.ItemsSource = comparison.Files
            .Select((file, index) => new ComparisonFileOption(index, FileLabel(file, index)))
            .ToArray();
        ComparisonExportButton.IsEnabled = true;
        ComparisonFileSelector.IsEnabled = true;
        if (comparison.Files.Length > 0)
            ComparisonFileSelector.SelectedIndex = 0;
    }

    private void ComparisonFileSelector_SelectionChanged(
        object sender, SelectionChangedEventArgs e)
    {
        ComparisonChangeList.SelectedIndex = -1;
        ComparisonChangeList.ItemsSource = null;
        ComparisonEvidenceText.Text = "Choose a finding change.";
        ComparisonChangeHintText.Text = "No finding changes to display.";

        if (_currentComparison is not BatchReportComparison comparison ||
            ComparisonFileSelector.SelectedItem is not ComparisonFileOption option)
        {
            ComparisonFileStatusText.Text = "No file selected.";
            ComparisonFileCountsText.Text = "";
            return;
        }

        ComparedFile file = comparison.Files[option.Index];
        ComparisonFileStatusText.Text = $"{file.Status}: {file.Explanation}";
        ComparisonFileCountsText.Text =
            $"Baseline findings: {CountLabel(file.BaselineFindingCount)}  |  " +
            $"Current findings: {CountLabel(file.CurrentFindingCount)}  |  " +
            $"Baseline diagnostics: {CountLabel(file.BaselineDiagnosticCount)}  |  " +
            $"Current diagnostics: {CountLabel(file.CurrentDiagnosticCount)}";

        ComparisonChangeList.ItemsSource = file.FindingChanges
            .Select(change => new ComparisonChangeOption(change,
                $"{change.Kind} ×{change.Count}  ·  {change.RuleId}",
                change.Title)).ToArray();
        ComparisonChangeHintText.Text = file.Status == ComparedFileStatus.Compared
            ? file.FindingChanges.Length == 0
                ? "No supported finding changes in this compared file. This is not a safety verdict."
                : "Select a change to inspect its evidence."
            : "No trustworthy finding deltas are available for this file status.";

        if (file.FindingChanges.Length > 0)
            ComparisonChangeList.SelectedIndex = 0;
    }

    private static string CountLabel(int? value) => value?.ToString() ?? "n/a";

    private void ComparisonChangeList_SelectionChanged(
        object sender, SelectionChangedEventArgs e)
    {
        if (ComparisonChangeList.SelectedItem is ComparisonChangeOption option)
        {
            ComparisonEvidenceText.Text = option.Change.Evidence;
            ComparisonChangeHintText.Text =
                $"{option.Change.Kind}: {option.Change.Title} ({option.Change.Count} occurrence(s)).";
        }
    }

    private async void ComparisonExport_Click(object sender, RoutedEventArgs e)
    {
        if (_isAnalyzing || _currentComparison is null) return;

        try
        {
            Window window = ((App)Application.Current).CurrentWindow
                ?? throw new InvalidOperationException("The application window is not available.");
            var picker = new FileSavePicker
            {
                SuggestedStartLocation = PickerLocationId.DocumentsLibrary,
                SuggestedFileName = "bomb-squad-comparison"
            };
            picker.FileTypeChoices.Add("JSON report", new List<string> { ".json" });
            InitializeWithWindow.Initialize(picker, WindowNative.GetWindowHandle(window));
            StorageFile? selectedFile = await picker.PickSaveFileAsync();
            if (selectedFile is null) return;

            SetBusy(true);
            string json = BatchReportComparisonJsonWriter.Serialize(_currentComparison);
            await FileIO.WriteTextAsync(selectedFile, json + Environment.NewLine,
                Windows.Storage.Streams.UnicodeEncoding.Utf8);
            ComparisonStatusText.Text =
                $"Comparison saved: {selectedFile.Name}. Export may contain source evidence and local paths.";
        }
        catch (Exception ex)
        {
            ComparisonStatusText.Text = $"Comparison export failed: {ex.Message}";
        }
        finally
        {
            SetBusy(false);
        }
    }
}
