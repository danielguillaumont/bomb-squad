using BombSquad.Analysis;
using BombSquad.Core;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace BombSquad_Desktop;

public sealed partial class MainPage
{
    private void OpenPaste_Click(object sender, RoutedEventArgs e)
    {
        if (_isAnalyzing)
        {
            return;
        }

        PasteInputPanel.Visibility = Visibility.Visible;
        PasteStatusText.Text = "";
        PasteSourceTextBox.Focus(FocusState.Programmatic);
    }

    private void ClosePaste_Click(object sender, RoutedEventArgs e)
    {
        if (_isAnalyzing)
        {
            return;
        }

        PasteInputPanel.Visibility = Visibility.Collapsed;
        PasteStatusText.Text = "";
    }

    private async void InspectPaste_Click(object sender, RoutedEventArgs e)
    {
        if (_isAnalyzing)
        {
            return;
        }

        string sourceText;
        try
        {
            // Validate before changing any inspection state: rejected input
            // must not destroy the current results or batch selection.
            sourceText = PastedPowerShellInput.Validate(PasteSourceTextBox.Text);
        }
        catch (System.Text.EncoderFallbackException)
        {
            PasteStatusText.Text = "Input error: pasted source contains invalid Unicode.";
            return;
        }
        catch (ArgumentException ex)
        {
            PasteStatusText.Text = $"Input error: {ex.Message}";
            return;
        }

        SetBusy(true);
        PasteStatusText.Text = "Inspecting pasted source as text; no PowerShell runs...";

        try
        {
            AnalysisResult result = await Task.Run(() => _analysisService.Analyze(
                new AnalysisRequest(sourceText, PastedPowerShellInput.SourceIdentifier)));

            ExitBatchMode();
            ShowAnalysis(result, "Pasted snippet (not saved)",
                PastedPowerShellInput.SourceIdentifier, sourceText);
            PasteStatusText.Text = "";
            PasteInputPanel.Visibility = Visibility.Collapsed;
        }
        catch (Exception ex)
        {
            // Unexpected parser failure is not a clean analysis result.
            ClearAnalysis();
            ParseStatusText.Text = $"Pasted inspection failed: {ex.Message}";
            PasteStatusText.Text = "Inspection did not complete. No source was executed.";
        }
        finally
        {
            SetBusy(false);
        }
    }
}
