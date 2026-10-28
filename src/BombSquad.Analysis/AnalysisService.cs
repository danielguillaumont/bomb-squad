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

        // Evaluate possible built-in matches, then withhold a match only
        // when that candidate's name collides with a source-defined function.
        // Benign helper-function calls do not become spurious warnings.
        ImmutableArray<Finding> candidateFindings = hasSyntaxErrors
            ? ImmutableArray<Finding>.Empty
            : _ruleEngine.Evaluate(parsed.Commands);

        var ambiguousOffsets = parsed.Commands
            .Where(command => command.MayBeShadowedBySourceFunction)
            .Select(command => command.Span.StartOffset)
            .ToHashSet();

        ImmutableArray<Finding> evaluatedFindings = candidateFindings
            .Where(finding => !ambiguousOffsets.Contains(
                finding.SourceSpan.StartOffset))
            .ToImmutableArray();

        var insideDefinitionOffsets = parsed.Commands
            .Where(command => command.IsInsideFunctionDefinition)
            .Select(command => command.Span.StartOffset)
            .ToHashSet();

        ImmutableArray<Finding> findings = evaluatedFindings
            .Select(finding => insideDefinitionOffsets.Contains(
                    finding.SourceSpan.StartOffset)
                ? finding with
                {
                    Limitations = finding.Limitations.Add(
                        "This command is inside a function definition. " +
                        "Defining the function does not call it; " +
                        "whether this function is invoked is unknown.")
                }
                : finding)
            .ToImmutableArray();

        var unsupportedConstructs = parsed.Commands
            .Where(command => command.CommandName is null)
            .Select(command =>
                $"Unresolved command name at line " +
                $"{command.Span.StartLine}, " +
                $"column {command.Span.StartColumn}.")
            .ToImmutableArray();

        var suppressedOffsets = candidateFindings
            .Where(finding => ambiguousOffsets.Contains(
                finding.SourceSpan.StartOffset))
            .Select(finding => finding.SourceSpan.StartOffset)
            .ToHashSet();

        var shadowedCommands = parsed.Commands
            .Where(command => suppressedOffsets.Contains(command.Span.StartOffset))
            .ToImmutableArray();

        unsupportedConstructs = unsupportedConstructs.AddRange(
            shadowedCommands.Select(command =>
                $"Command '{command.CommandName}' at line " +
                $"{command.Span.StartLine}, column {command.Span.StartColumn} " +
                "matches a function name defined in this source. " +
                "Built-in-specific detection was withheld; " +
                "scope and invocation order are unresolved."));

        var limitations = ImmutableArray.Create(
            "This is a partial rule set. Six rule IDs are active: " +
            "BS-FS-001, BS-SS-001, BS-RG-001, BS-ID-001, BS-TS-001, and BS-DE-001.",
            "Only selected filesystem, Defender, registry, identity, " +
            "tasks/services, and dynamic execution patterns are detected.",
            "Tasks/services coverage currently includes only " +
            "Register-ScheduledTask, New-Service, and Set-Service.",
            "Dynamic execution coverage includes Invoke-Expression, iex, " +
            "and expression-based call or dot-source invocations.",
            "Evaluated text and dynamic invocation targets are not resolved.",
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

        if (parsed.Commands.Any(command => command.IsInsideFunctionDefinition))
        {
            limitations = limitations.Add(
                "Some commands occur inside function definitions. " +
                "Definition is not execution and function reachability is not analyzed.");
        }

        if (!shadowedCommands.IsEmpty)
        {
            limitations = limitations.Add(
                "Commands whose names match functions defined in this source " +
                "were excluded from built-in-specific rules. " +
                "This conservative file-wide check does not resolve lexical scope, " +
                "declaration order, or actual runtime command binding.");
        }

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
