using System.Collections.Immutable;
using System.Text.RegularExpressions;
using BombSquad.Core;

namespace BombSquad.Rules;

public sealed class RegistryPropertyRule : IFindingRule
{
    private static readonly Regex RegistryPathPattern = new(
        """(?<![\w-])-(?:LiteralPath|Path)\s+['"]?(?:(?:HKLM|HKCU|HKCR|HKU|HKCC):[\\/]|Registry::HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)[\\/])""",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant
    );

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

            if (!isMutation ||
                !RegistryPathPattern.IsMatch(command.Text))
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
                    "Registry paths are recognized from literal source text.",
                    "PowerShell parameter binding and runtime values are not resolved.",
                    "Path-like text inside other arguments may cause false positives.",
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
}
