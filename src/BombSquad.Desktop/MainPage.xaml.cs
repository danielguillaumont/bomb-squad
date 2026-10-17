using BombSquad.Analysis;
using BombSquad.Core;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace BombSquad_Desktop;

public sealed partial class MainPage : Page
{
    private readonly AnalysisService _analysisService = new();

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

    private void RunDemo_Click(
        object sender,
        RoutedEventArgs e)
    {
        try
        {
            AnalysisResult result = _analysisService.Analyze(
                new AnalysisRequest(
                    DemoScript,
                    "desktop-demo.ps1"
                )
            );

            SourceNameText.Text = "desktop-demo.ps1 (built-in sample)";

            CommandCountText.Text =
                result.Commands.Length.ToString();

            FindingCountText.Text =
                result.Findings.Length.ToString();

            DiagnosticCountText.Text =
                result.Diagnostics.Length.ToString();

            ParseStatusText.Text =
                $"Status: {result.Status} | " +
                $"Rules skipped: {result.RulesSkipped} | " +
                $"Engine: {result.EngineVersion}";

            FindingsList.ItemsSource = result.Findings.ToArray();

            if (result.Findings.Length > 0)
            {
                FindingsList.SelectedIndex = 0;
            }
            else
            {
                DetailsTitleText.Text = "No findings detected";
                LocationText.Text = "No matching rule locations";
                EvidenceText.Text = "No matching evidence";
                PotentialEffectText.Text =
                    "No supported rules matched this source.";
                LimitationsText.Text =
                    "This is a partial rule set. " +
                    "No findings does not establish safety.";
                NextStepText.Text =
                    "Review the full script and its execution context.";
            }
        }
        catch (Exception ex)
        {
            ParseStatusText.Text =
                $"Analysis failed: {ex.Message}";
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

        DetailsTitleText.Text =
            $"{finding.RuleId} · {finding.Title}";

        LocationText.Text =
            $"{finding.Family} | " +
            $"Line {finding.SourceSpan.StartLine}, " +
            $"Column {finding.SourceSpan.StartColumn} | " +
            $"{finding.Certainty}";

        EvidenceText.Text = finding.Evidence;

        PotentialEffectText.Text = finding.PotentialEffect;

        LimitationsText.Text = string.Join(
            Environment.NewLine,
            finding.Limitations.Select(
                limitation => $"• {limitation}"
            )
        );

        NextStepText.Text = finding.NextStep;
    }
}
