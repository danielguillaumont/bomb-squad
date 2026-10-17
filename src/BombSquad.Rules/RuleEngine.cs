using System.Collections.Immutable;
using BombSquad.Core;

namespace BombSquad.Rules;

public sealed class RuleEngine
{
    private readonly ImmutableArray<IFindingRule> _rules;

    public RuleEngine()
        : this(new IFindingRule[]
        {
            new RemoveItemRule(),
            new DefenderPreferenceRule()
        })
    {
    }

    public RuleEngine(IEnumerable<IFindingRule> rules)
    {
        ArgumentNullException.ThrowIfNull(rules);

        _rules = rules.ToImmutableArray();

        if (_rules.IsEmpty)
        {
            throw new ArgumentException(
                "At least one detection rule is required.",
                nameof(rules)
            );
        }

        if (_rules.Any(rule => rule is null))
        {
            throw new ArgumentException(
                "Detection rules cannot contain null entries.",
                nameof(rules)
            );
        }
    }

    public ImmutableArray<Finding> Evaluate(
        IReadOnlyList<ParsedCommand> commands)
    {
        ArgumentNullException.ThrowIfNull(commands);

        var findings = ImmutableArray.CreateBuilder<Finding>();

        foreach (IFindingRule rule in _rules)
        {
            findings.AddRange(rule.Evaluate(commands));
        }

        return findings
            .OrderBy(finding => finding.SourceSpan.StartOffset)
            .ThenBy(finding => finding.RuleId, StringComparer.Ordinal)
            .ToImmutableArray();
    }
}
