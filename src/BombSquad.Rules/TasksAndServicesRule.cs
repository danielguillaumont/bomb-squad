using System.Collections.Immutable;
using BombSquad.Core;

namespace BombSquad.Rules;

public sealed class TasksAndServicesRule : IFindingRule
{
    public string RuleId => "BS-TS-001";

    public ImmutableArray<Finding> Evaluate(
        IReadOnlyList<ParsedCommand> commands)
    {
        ArgumentNullException.ThrowIfNull(commands);

        var findings = ImmutableArray.CreateBuilder<Finding>();

        foreach (ParsedCommand command in commands)
        {
            bool isTaskRegistration = string.Equals(
                command.CommandName,
                "Register-ScheduledTask",
                StringComparison.OrdinalIgnoreCase
            );

            bool isServiceCreation = string.Equals(
                command.CommandName,
                "New-Service",
                StringComparison.OrdinalIgnoreCase
            );

            bool isServiceConfiguration = string.Equals(
                command.CommandName,
                "Set-Service",
                StringComparison.OrdinalIgnoreCase
            );

            if (!isTaskRegistration &&
                !isServiceCreation &&
                !isServiceConfiguration)
            {
                continue;
            }

            string title;
            string potentialEffect;

            if (isTaskRegistration)
            {
                title = "Potential scheduled task registration";

                potentialEffect =
                    "If executed as the intended Windows cmdlet, " +
                    "this operation could register or update a " +
                    "scheduled task that runs according to its configuration.";
            }
            else if (isServiceCreation)
            {
                title = "Potential Windows service creation";

                potentialEffect =
                    "If executed as the intended Windows cmdlet, " +
                    "this operation could create a Windows service " +
                    "using the supplied configuration.";
            }
            else
            {
                title = "Potential Windows service configuration change";

                potentialEffect =
                    "If executed as the intended Windows cmdlet, " +
                    "this operation could modify an existing " +
                    "Windows service's configuration or state.";
            }

            findings.Add(new Finding(
                Id: $"{RuleId}:{command.Span.StartOffset}:{command.Span.EndOffset}",
                RuleId: RuleId,
                Title: title,
                Family: FindingFamily.TasksAndServices,
                ReviewLevel: ReviewLevel.Review,
                Certainty: Certainty.Conditional,
                SourceSpan: command.Span,
                Evidence: command.Text,
                PotentialEffect: potentialEffect,
                Limitations: ImmutableArray.Create(
                    "Command presence does not prove execution.",
                    "The target task or service is not resolved.",
                    "Task actions, triggers, and service executable paths are not verified.",
                    "Creation, persistence, or configuration changes are not confirmed.",
                    "Parameters, WhatIf behavior, and runtime control flow are not evaluated.",
                    "Aliases, custom functions, and command shadowing are not resolved.",
                    "No Windows tasks or services were inspected or modified."
                ),
                NextStep:
                    "Review the task or service name, intended behavior, " +
                    "execution context, persistence implications, " +
                    "and authorization before executing."
            ));
        }

        return findings.ToImmutable();
    }
}
