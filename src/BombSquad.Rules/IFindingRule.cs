using System.Collections.Immutable;
using BombSquad.Core;

namespace BombSquad.Rules;

public interface IFindingRule
{
    string RuleId { get; }

    ImmutableArray<Finding> Evaluate(
        IReadOnlyList<ParsedCommand> commands
    );
}
