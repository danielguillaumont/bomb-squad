using System.Collections.Immutable;
using BombSquad.Core;

namespace BombSquad.Rules;

public sealed class RegistryPropertyRule : IFindingRule
{
    private static readonly string[] RegistryPrefixes =
    {
        @"HKLM:\", "HKLM:/",
        @"HKCU:\", "HKCU:/",
        @"HKCR:\", "HKCR:/",
        @"HKU:\", "HKU:/",
        @"HKCC:\", "HKCC:/",
        @"Registry::HKEY_LOCAL_MACHINE\",
        "Registry::HKEY_LOCAL_MACHINE/",
        @"Registry::HKEY_CURRENT_USER\",
        "Registry::HKEY_CURRENT_USER/",
        @"Registry::HKEY_CLASSES_ROOT\",
        "Registry::HKEY_CLASSES_ROOT/",
        @"Registry::HKEY_USERS\",
        "Registry::HKEY_USERS/",
        @"Registry::HKEY_CURRENT_CONFIG\",
        "Registry::HKEY_CURRENT_CONFIG/"
    };

    public string RuleId => "BS-RG-001";

    public ImmutableArray<Finding> Evaluate(
        IReadOnlyList<ParsedCommand> commands)
    {
        ArgumentNullException.ThrowIfNull(commands);

        var findings = ImmutableArray.CreateBuilder<Finding>();

        foreach (ParsedCommand command in commands)
        {
            bool isMutation =
                string.Equals(
                    command.CommandName,
                    "Set-ItemProperty",
                    StringComparison.OrdinalIgnoreCase
                ) ||
                string.Equals(
                    command.CommandName,
                    "New-ItemProperty",
                    StringComparison.OrdinalIgnoreCase
                ) ||
                string.Equals(
                    command.CommandName,
                    "Remove-ItemProperty",
                    StringComparison.OrdinalIgnoreCase
                );

            if (!isMutation || !HasExplicitRegistryPath(command))
            {
                continue;
            }

            findings.Add(new Finding(
                Id: $"{RuleId}:{command.Span.StartOffset}:{command.Span.EndOffset}",
                RuleId: RuleId,
                Title: "Potential registry property modification",
                Family: FindingFamily.Registry,
                ReviewLevel: ReviewLevel.Review,
                Certainty: Certainty.Conditional,
                SourceSpan: command.Span,
                Evidence: command.Text,
                PotentialEffect:
                    "If executed against the Windows Registry provider, " +
                    "this operation could create, change, or remove " +
                    "a registry property.",
                Limitations: ImmutableArray.Create(
                    "Command presence does not prove execution.",
                    "Only explicitly named literal registry paths are detected.",
                    "Positional and dynamically computed paths are not resolved.",
                    "PowerShell parameter binding and runtime effects are not verified.",
                    "Aliases, command shadowing, and control flow are not resolved.",
                    "The registry was not accessed or modified."
                ),
                NextStep:
                    "Review the target registry hive, property name, " +
                    "proposed value, and authorization before executing."
            ));
        }

        return findings.ToImmutable();
    }

    private static bool HasExplicitRegistryPath(ParsedCommand command)
    {
        return command.LiteralParameters.Any(parameter =>
            (
                string.Equals(
                    parameter.Name,
                    "Path",
                    StringComparison.OrdinalIgnoreCase
                ) ||
                string.Equals(
                    parameter.Name,
                    "LiteralPath",
                    StringComparison.OrdinalIgnoreCase
                )
            ) &&
            RegistryPrefixes.Any(prefix =>
                parameter.Value.StartsWith(
                    prefix,
                    StringComparison.OrdinalIgnoreCase
                )
            )
        );
    }
}
