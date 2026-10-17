using System.Collections.Immutable;
using BombSquad.Core;

namespace BombSquad.Rules;

public sealed class DefenderPreferenceRule : IFindingRule
{
    public string RuleId => "BS-SS-001";

    public ImmutableArray<Finding> Evaluate(
        IReadOnlyList<ParsedCommand> commands)
    {
        ArgumentNullException.ThrowIfNull(commands);

        var findings = ImmutableArray.CreateBuilder<Finding>();

        foreach (ParsedCommand command in commands)
        {
            bool isSetPreference = string.Equals(
                command.CommandName,
                "Set-MpPreference",
                StringComparison.OrdinalIgnoreCase
            );

            bool isAddPreference = string.Equals(
                command.CommandName,
                "Add-MpPreference",
                StringComparison.OrdinalIgnoreCase
            );

            if (!isSetPreference && !isAddPreference)
            {
                continue;
            }

            findings.Add(new Finding(
                Id: $"{RuleId}:{command.Span.StartOffset}:{command.Span.EndOffset}",
                RuleId: RuleId,
                Title: "Potential Defender configuration change",
                Family: FindingFamily.SecuritySettings,
                ReviewLevel: ReviewLevel.Review,
                Certainty: Certainty.Conditional,
                SourceSpan: command.Span,
                Evidence: command.Text,
                PotentialEffect:
                    "If executed as a Microsoft Defender cmdlet, " +
                    "this operation could modify antivirus preferences, " +
                    "including protection settings or exclusions.",
                Limitations: ImmutableArray.Create(
                    "Command presence does not prove execution.",
                    "The effective Defender configuration is not inspected.",
                    "Parameter values and runtime control flow are not evaluated.",
                    "Custom functions and command shadowing are not resolved.",
                    "The change may strengthen or weaken protection."
                ),
                NextStep:
                    "Review the requested Defender preference, " +
                    "its parameters, the execution context, and " +
                    "whether the proposed configuration is authorized."
            ));
        }

        return findings.ToImmutable();
    }
}
