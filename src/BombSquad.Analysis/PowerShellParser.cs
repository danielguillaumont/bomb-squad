using System.Collections.Immutable;
using System.Management.Automation.Language;
using BombSquad.Core;

namespace BombSquad.Analysis;

public sealed class PowerShellParser
{
    public PowerShellParseResult Parse(string source)
    {
        ArgumentNullException.ThrowIfNull(source);

        ScriptBlockAst ast = Parser.ParseInput(
            source,
            out _,
            out ParseError[] errors
        );

        // A static function declaration can change command-name resolution.
        // Conservatively collect declarations across this source rather than
        // asserting that a particular built-in cmdlet will be invoked.
        var declaredFunctionNames = ast
            .FindAll(node => node is FunctionDefinitionAst,
                searchNestedScriptBlocks: true)
            .OfType<FunctionDefinitionAst>()
            .Select(definition => definition.Name)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var commands = ast
            .FindAll(
                node => node is CommandAst,
                searchNestedScriptBlocks: true
            )
            .OfType<CommandAst>()
            .Select(command => new ParsedCommand(
                CommandName: command.GetCommandName(),
                Text: command.Extent.Text,
                Span: ToSourceSpan(command.Extent)
            )
            {
                LiteralParameters = ExtractLiteralParameters(command),
                IsDynamicInvocation = IsDynamicInvocation(command),
                IsInsideFunctionDefinition = IsInsideFunctionDefinition(command),
                MayBeShadowedBySourceFunction =
                    command.GetCommandName() is string name &&
                    declaredFunctionNames.Contains(name)
            })
            .ToImmutableArray();

        var diagnostics = errors
            .Select(error => new ParseDiagnostic(
                Code: error.ErrorId,
                Message: error.Message,
                SourceSpan: ToSourceSpan(error.Extent)
            ))
            .ToImmutableArray();

        return new PowerShellParseResult(
            Commands: commands,
            Diagnostics: diagnostics
        );
    }

    private static bool IsInsideFunctionDefinition(CommandAst command)
    {
        for (Ast? parent = command.Parent; parent is not null;
             parent = parent.Parent)
        {
            if (parent is FunctionDefinitionAst)
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsDynamicInvocation(CommandAst command)
    {
        bool usesInvocationOperator =
            command.InvocationOperator is TokenKind.Ampersand or TokenKind.Dot;

        if (!usesInvocationOperator ||
            command.CommandElements.Count == 0)
        {
            return false;
        }

        return command.CommandElements[0]
            is not StringConstantExpressionAst;
    }
    private static ImmutableArray<ParsedLiteralParameter>
        ExtractLiteralParameters(CommandAst command)
    {
        var parameters =
            ImmutableArray.CreateBuilder<ParsedLiteralParameter>();

        for (int i = 0; i < command.CommandElements.Count; i++)
        {
            if (command.CommandElements[i] is not CommandParameterAst parameter)
            {
                continue;
            }

            ExpressionAst? argument = parameter.Argument;

            if (argument is null &&
                i + 1 < command.CommandElements.Count)
            {
                argument =
                    command.CommandElements[i + 1] as ExpressionAst;
            }

            if (argument is not StringConstantExpressionAst literal)
            {
                continue;
            }

            parameters.Add(new ParsedLiteralParameter(
                Name: parameter.ParameterName,
                Value: literal.Value
            ));
        }

        return parameters.ToImmutable();
    }

    private static SourceSpan ToSourceSpan(IScriptExtent extent)
    {
        return new SourceSpan(
            StartOffset: extent.StartOffset,
            EndOffset: extent.EndOffset,
            StartLine: extent.StartLineNumber,
            StartColumn: extent.StartColumnNumber,
            EndLine: extent.EndLineNumber,
            EndColumn: extent.EndColumnNumber
        );
    }
}
