using System.Collections.Immutable;
using BombSquad.Core;
using BombSquad.Rules;

namespace BombSquad.Analysis;

public sealed class AnalysisService
{
    private readonly PowerShellParser _parser = new();
    private readonly RuleEngine _ruleEngine = new();

    public AnalysisResult Analyze(AnalysisRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(request.SourceText);

        PowerShellParseResult parsed = _parser.Parse(
            request.SourceText
        );

        bool hasSyntaxErrors = !parsed.Diagnostics.IsEmpty;

        AnalysisStatus status = hasSyntaxErrors
            ? AnalysisStatus.ParsedWithErrors
            : AnalysisStatus.Parsed;

        ImmutableArray<Finding> findings = hasSyntaxErrors
            ? ImmutableArray<Finding>.Empty
            : _ruleEngine.Evaluate(parsed.Commands);

        var unsupportedConstructs = parsed.Commands
            .Where(command => command.CommandName is null)
            .Select(command =>
                $"Unresolved command name at line " +
                $"{command.Span.StartLine}, " +
                $"column {command.Span.StartColumn}.")
            .ToImmutableArray();

        var limitations = ImmutableArray.Create(
            "This is a partial rule set. Four rule IDs are active: " +
            "BS-FS-001, BS-SS-001, BS-RG-001, and BS-ID-001.",
            "Only selected filesystem, Defender, registry property, " +
            "and local identity command patterns are detected.",
            "Tasks/services and dynamic execution detection families " +
            "are not yet implemented.",
            "Registry paths are identified from AST-backed named literal " +
            "-Path or -LiteralPath arguments.",
            "Positional and dynamic registry paths, aliases, " +
            "parameter binding, and runtime behavior remain unresolved.",
            "Aliases, command shadowing, target providers, " +
            "parameters, and runtime control flow are not resolved.",
            "Dynamic or unresolved commands may be missed.",
            "Findings indicate potential operations, not " +
            "confirmed execution or effects.",
            "The absence of findings does not establish safety."
        );

        if (hasSyntaxErrors)
        {
            limitations = limitations.Add(
                "Detection rules were skipped because parser " +
                "errors were reported. Partial AST commands " +
                "may still be displayed."
            );
        }

        return new AnalysisResult(
            Status: status,
            Findings: findings,
            Diagnostics: parsed.Diagnostics,
            UnsupportedConstructs: unsupportedConstructs,
            Limitations: limitations,
            EngineVersion: "0.2.0-dev",
            RuleSetVersion: "0.2.0-dev",
            RulesSkipped: hasSyntaxErrors
        )
        {
            Commands = parsed.Commands
        };
    }
}
