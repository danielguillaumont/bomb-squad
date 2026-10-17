using System.Collections.Immutable;
using BombSquad.Core;

namespace BombSquad.Rules;

public sealed class RemoveItemRule : IFindingRule
{
    public string RuleId => "BS-FS-001";

    public ImmutableArray<Finding> Evaluate(
        IReadOnlyList<ParsedCommand> commands)
    {
        ArgumentNullException.ThrowIfNull(commands);

        var findings = ImmutableArray.CreateBuilder<Finding>();

        foreach (ParsedCommand command in commands)
        {
            if (!string.Equals(
                command.CommandName,
                "Remove-Item",
                StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            findings.Add(new Finding(
                Id: $"{RuleId}:{command.Span.StartOffset}:{command.Span.EndOffset}",
                RuleId: RuleId,
                Title: "Potential item deletion",
                Family: FindingFamily.Filesystem,
                ReviewLevel: ReviewLevel.Review,
                Certainty: Certainty.Conditional,
                SourceSpan: command.Span,
                Evidence: command.Text,
                PotentialEffect:
                    "If executed against the filesystem, this command " +
                    "could delete files or directories.",
                Limitations: ImmutableArray.Create(
                    "Command presence does not prove execution.",
                    "The target PowerShell provider and path are not resolved.",
                    "Arguments, WhatIf behavior, and control flow are not evaluated.",
                    "Custom functions and command shadowing are not resolved."
                ),
                NextStep:
                    "Review the target, parameters, and surrounding " +
                    "control flow before executing this script."
            ));
        }

        return findings.ToImmutable();
    }
}
