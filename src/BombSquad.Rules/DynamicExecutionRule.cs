using System.Collections.Immutable;
using BombSquad.Core;

namespace BombSquad.Rules;

public sealed class DynamicExecutionRule : IFindingRule
{
    public string RuleId => "BS-DE-001";

    public ImmutableArray<Finding> Evaluate(
        IReadOnlyList<ParsedCommand> commands)
    {
        ArgumentNullException.ThrowIfNull(commands);

        var findings = ImmutableArray.CreateBuilder<Finding>();

        foreach (ParsedCommand command in commands)
        {
            bool isInvokeExpression =
                string.Equals(
                    command.CommandName,
                    "Invoke-Expression",
                    StringComparison.OrdinalIgnoreCase
                ) ||
                string.Equals(
                    command.CommandName,
                    "iex",
                    StringComparison.OrdinalIgnoreCase
                );

            bool isExpressionInvocation = command.IsDynamicInvocation;

            if (!isInvokeExpression && !isExpressionInvocation)
            {
                continue;
            }

            string title = isInvokeExpression
                ? "Potential PowerShell text evaluation"
                : "Potential expression-based command invocation";

            string potentialEffect = isInvokeExpression
                ? "If executed as the intended PowerShell command, " +
                  "this operation could evaluate supplied text as " +
                  "PowerShell code."
                : "If executed, this expression-based invocation " +
                  "could call a command, script, or script block " +
                  "whose effective behavior requires further analysis.";

            findings.Add(new Finding(
                Id: $"{RuleId}:{command.Span.StartOffset}:{command.Span.EndOffset}",
                RuleId: RuleId,
                Title: title,
                Family: FindingFamily.DynamicExecution,
                ReviewLevel: ReviewLevel.Review,
                Certainty: Certainty.Conditional,
                SourceSpan: command.Span,
                Evidence: command.Text,
                PotentialEffect: potentialEffect,
                Limitations: ImmutableArray.Create(
                    "Command presence does not prove execution.",
                    "The evaluated text or effective invocation target is not resolved.",
                    "The actual command implementation and runtime effects are unknown.",
                    "Variables, expressions, aliases, and command shadowing are not resolved.",
                    "Control flow and the origin of dynamic inputs are not evaluated.",
                    "This rule does not cover every dynamic execution mechanism.",
                    "No supplied PowerShell source was executed."
                ),
                NextStep:
                    "Trace the source of the command or script content, " +
                    "review any external input and surrounding control flow, " +
                    "and verify its intended behavior before execution."
            ));
        }

        return findings.ToImmutable();
    }
}
