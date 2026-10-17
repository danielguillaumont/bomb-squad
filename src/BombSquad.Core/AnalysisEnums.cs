namespace BombSquad.Core;

public enum AnalysisStatus
{
    NotImplemented,
    Parsed,
    ParsedWithErrors,
    PartiallyAnalyzed,
    BlockedByInputConstraint
}

public enum FindingFamily
{
    Filesystem,
    SecuritySettings,
    Identity,
    TasksAndServices,
    Registry,
    DynamicExecution
}

public enum ReviewLevel
{
    Informational,
    Review,
    High
}

public enum Certainty
{
    Direct,
    Conditional,
    Unresolved
}
