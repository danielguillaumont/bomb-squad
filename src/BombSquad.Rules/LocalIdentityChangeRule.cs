using System.Collections.Immutable;
using BombSquad.Core;

namespace BombSquad.Rules;

public sealed class LocalIdentityChangeRule : IFindingRule
{
    public string RuleId => "BS-ID-001";

    public ImmutableArray<Finding> Evaluate(
        IReadOnlyList<ParsedCommand> commands)
    {
        ArgumentNullException.ThrowIfNull(commands);

        var findings = ImmutableArray.CreateBuilder<Finding>();

        foreach (ParsedCommand command in commands)
        {
            bool isAccountCreation = string.Equals(
                command.CommandName,
                "New-LocalUser",
                StringComparison.OrdinalIgnoreCase
            );

            bool isGroupAddition = string.Equals(
                command.CommandName,
                "Add-LocalGroupMember",
                StringComparison.OrdinalIgnoreCase
            );

            if (!isAccountCreation && !isGroupAddition)
            {
                continue;
            }

            findings.Add(new Finding(
                Id: $"{RuleId}:{command.Span.StartOffset}:{command.Span.EndOffset}",
                RuleId: RuleId,
                Title: "Potential local identity change",
                Family: FindingFamily.Identity,
                ReviewLevel: ReviewLevel.Review,
                Certainty: Certainty.Conditional,
                SourceSpan: command.Span,
                Evidence: command.Text,
                PotentialEffect:
                    "If resolved to the intended Windows cmdlet " +
                    "and executed, this operation could create " +
                    "a local user or add a member to a local group.",
                Limitations: ImmutableArray.Create(
                    "Command presence does not prove execution.",
                    "The target user and group are not resolved.",
                    "Administrative privilege changes are not confirmed.",
                    "Parameters, WhatIf behavior, and runtime control flow are not evaluated.",
                    "Aliases, custom functions, and command shadowing are not resolved.",
                    "Local account and group state was not inspected or modified."
                ),
                NextStep:
                    "Review the target account, requested group membership, " +
                    "authorization, and surrounding control flow before execution."
            ));
        }

        return findings.ToImmutable();
    }
}
