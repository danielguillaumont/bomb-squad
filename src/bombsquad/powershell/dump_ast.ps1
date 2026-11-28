# Bomb Squad PowerShell AST dumper.
#
# Input on stdin: base64 of UTF-8 JSON {"documents": [{"id": "...", "text": "..."}]}.
# Output on stdout: base64 of UTF-8 JSON with what the parser saw in each document.
#
# This script only calls Parser.ParseInput and walks the resulting syntax tree.
# Nothing from the input is evaluated, invoked, imported or written anywhere.
# `using module` and `using assembly` statements are blanked by the caller before
# parsing, because the parser reads the files they name.
# String folding below is done here, on literal values only, never by PowerShell.
# Compatible with Windows PowerShell 5.1 and PowerShell 7.

$ErrorActionPreference = 'Stop'

$MaxFolded = 1000000

function Get-Span($extent) {
    [ordered]@{
        start      = $extent.StartOffset
        end        = $extent.EndOffset
        line       = $extent.StartLineNumber
        column     = $extent.StartColumnNumber
        end_line   = $extent.EndLineNumber
        end_column = $extent.EndColumnNumber
    }
}

# A type name as written. FullName parses an assembly-qualified name such as
# [Foo, Bar=...] and throws on a malformed one, so the plain name is the fallback.
function Get-TypeName($typeName) {
    try { return [string]$typeName.FullName } catch { }
    try { return [string]$typeName.Name } catch { return '' }
}

# Returns a folded string for an expression built only from literals, or $null.
function Get-Folded($node) {
    if ($null -eq $node) { return $null }
    $type = $node.GetType().Name
    switch ($type) {
        'StringConstantExpressionAst' { return [string]$node.Value }
        'ExpandableStringExpressionAst' {
            if ($node.NestedExpressions.Count -eq 0) { return [string]$node.Value }
            return $null
        }
        'ConstantExpressionAst' {
            $v = $node.Value
            if ($v -is [string] -or $v -is [int] -or $v -is [long] -or $v -is [char]) { return [string]$v }
            return $null
        }
        'CommandExpressionAst' { return Get-Folded $node.Expression }
        'ParenExpressionAst' {
            $p = $node.Pipeline
            if ($p -is [System.Management.Automation.Language.PipelineAst] -and $p.PipelineElements.Count -eq 1) {
                return Get-Folded $p.PipelineElements[0]
            }
            return $null
        }
        'ConvertExpressionAst' {
            $tn = (Get-TypeName $node.Type.TypeName).ToLowerInvariant()
            if ($tn -eq 'string') { return Get-Folded $node.Child }
            if ($tn -eq 'char') {
                $c = $node.Child
                if ($c -is [System.Management.Automation.Language.ConstantExpressionAst] -and $c.Value -is [int]) {
                    if ($c.Value -ge 0 -and $c.Value -le 0xFFFF) { return [string][char]$c.Value }
                }
                return Get-Folded $c
            }
            return $null
        }
        'BinaryExpressionAst' {
            $op = $node.Operator.ToString()
            if ($op -eq 'Plus') {
                $a = Get-Folded $node.Left
                $b = Get-Folded $node.Right
                if ($null -eq $a -or $null -eq $b) { return $null }
                if ($a.Length + $b.Length -gt $MaxFolded) { return $null }
                return $a + $b
            }
            if ($op -eq 'Join') {
                $parts = Get-FoldedList $node.Left
                $sep = Get-Folded $node.Right
                if ($null -eq $parts -or $null -eq $sep) { return $null }
                return [string]::Join($sep, $parts)
            }
            if ($op -eq 'Format') {
                $fmt = Get-Folded $node.Left
                $fmtArgs = Get-FoldedList $node.Right
                if ($null -eq $fmt -or $null -eq $fmtArgs) { return $null }
                # Each {n} can repeat an argument, so bound the result before building it.
                $longest = 0
                foreach ($a in $fmtArgs) { if ($a.Length -gt $longest) { $longest = $a.Length } }
                $slots = ([regex]::Matches($fmt, '\{')).Count
                if ($fmt.Length + $slots * $longest -gt $MaxFolded) { return $null }
                try { return [string]::Format($fmt, [object[]]$fmtArgs) } catch { return $null }
            }
            return $null
        }
        'UnaryExpressionAst' {
            if ($node.TokenKind.ToString() -eq 'Join') {
                $parts = Get-FoldedList $node.Child
                if ($null -eq $parts) { return $null }
                return [string]::Join('', $parts)
            }
            return $null
        }
    }
    return $null
}

# Returns a list of folded strings for an array of literals, or $null.
function Get-FoldedList($node) {
    if ($null -eq $node) { return $null }
    $items = $null
    if ($node -is [System.Management.Automation.Language.ArrayLiteralAst]) {
        $items = $node.Elements
    } elseif ($node -is [System.Management.Automation.Language.ParenExpressionAst]) {
        $p = $node.Pipeline
        if ($p -is [System.Management.Automation.Language.PipelineAst] -and $p.PipelineElements.Count -eq 1) {
            return Get-FoldedList $p.PipelineElements[0]
        }
        return $null
    } elseif ($node -is [System.Management.Automation.Language.ArrayExpressionAst]) {
        $statements = $node.SubExpression.Statements
        if ($statements.Count -eq 1 -and $statements[0] -is [System.Management.Automation.Language.PipelineAst] -and
            $statements[0].PipelineElements.Count -eq 1) {
            return Get-FoldedList $statements[0].PipelineElements[0]
        }
        return $null
    } elseif ($node -is [System.Management.Automation.Language.CommandExpressionAst]) {
        return Get-FoldedList $node.Expression
    } elseif ($node -is [System.Management.Automation.Language.ConvertExpressionAst]) {
        $tn = (Get-TypeName $node.Type.TypeName).ToLowerInvariant()
        if ($tn -eq 'char[]') {
            $codes = Get-FoldedList $node.Child
            if ($null -eq $codes) { return $null }
            $chars = New-Object System.Collections.Generic.List[string]
            foreach ($code in $codes) {
                $n = 0
                if (-not [int]::TryParse($code, [ref]$n) -or $n -lt 0 -or $n -gt 0xFFFF) { return $null }
                $chars.Add([string][char]$n)
            }
            return ,$chars.ToArray()
        }
        return $null
    } else {
        $single = Get-Folded $node
        if ($null -eq $single) { return $null }
        return ,@($single)
    }
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($item in $items) {
        $v = Get-Folded $item
        if ($null -eq $v) { return $null }
        $out.Add($v)
    }
    return ,$out.ToArray()
}

function Get-VariableNames($node) {
    if ($null -eq $node) { return @() }
    $names = New-Object System.Collections.Generic.List[string]
    $found = $node.FindAll({ param($n) $n -is [System.Management.Automation.Language.VariableExpressionAst] }, $true)
    foreach ($v in $found) { $names.Add($v.VariablePath.UserPath) }
    return ,$names.ToArray()
}

function Get-NameChoices($command) {
    # `& $Tool` where $Tool is a parameter of the enclosing function, or of the script outside
    # any function, that [ValidateSet()] restricts to string literals: PowerShell refuses any
    # other value, so these are the commands it can run. Not when anything in that function
    # or script assigns the variable, which in a nested scope would make a new, unrestricted one.
    if ($command.InvocationOperator.ToString() -eq 'Unknown') { return $null }
    $first = $command.CommandElements[0]
    if ($first -isnot [System.Management.Automation.Language.VariableExpressionAst]) { return $null }
    $name = $first.VariablePath.UserPath
    $scope = $command.Parent
    while ($null -ne $scope -and $scope -isnot [System.Management.Automation.Language.FunctionDefinitionAst]) {
        if ($null -eq $scope.Parent) { break }
        $scope = $scope.Parent
    }
    $params = $null
    if ($scope -is [System.Management.Automation.Language.FunctionDefinitionAst]) {
        $params = if ($null -ne $scope.Parameters) { $scope.Parameters }
                  elseif ($null -ne $scope.Body.ParamBlock) { $scope.Body.ParamBlock.Parameters }
    } elseif ($scope -is [System.Management.Automation.Language.ScriptBlockAst] -and $null -ne $scope.ParamBlock) {
        $params = $scope.ParamBlock.Parameters
    }
    if ($null -eq $params) { return $null }
    $param = $params | Where-Object { $_.Name.VariablePath.UserPath -eq $name } | Select-Object -First 1
    if ($null -eq $param) { return $null }
    $assigned = $scope.FindAll({ param($n)
            ($n -is [System.Management.Automation.Language.AssignmentStatementAst] -and
             $n.Left -is [System.Management.Automation.Language.VariableExpressionAst] -and
             $n.Left.VariablePath.UserPath -eq $name) -or
            ($n -is [System.Management.Automation.Language.ForEachStatementAst] -and
             $n.Variable.VariablePath.UserPath -eq $name) }, $true)
    if (@($assigned).Count -gt 0) { return $null }
    foreach ($attr in $param.Attributes) {
        if ($attr -isnot [System.Management.Automation.Language.AttributeAst]) { continue }
        if ($attr.TypeName.Name -notin @('ValidateSet', 'System.Management.Automation.ValidateSet')) { continue }
        $values = @($attr.PositionalArguments)
        $literal = @($values | Where-Object { $_ -is [System.Management.Automation.Language.StringConstantExpressionAst] })
        if ($values.Count -gt 0 -and $literal.Count -eq $values.Count) {
            return ,[string[]]@($literal | ForEach-Object { $_.Value })
        }
    }
    return $null
}

function Get-PipelineInfo($command) {
    $parent = $command.Parent
    if ($parent -is [System.Management.Automation.Language.PipelineAst]) {
        return @{ span = (Get-Span $parent.Extent); index = $parent.PipelineElements.IndexOf($command) }
    }
    return @{ span = $null; index = 0 }
}

function ConvertTo-Document($doc) {
    $tokens = $null
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseInput([string]$doc.text, [ref]$tokens, [ref]$errors)

    $parseErrors = @(foreach ($e in $errors) {
        [ordered]@{ message = $e.Message; error_id = $e.ErrorId; span = (Get-Span $e.Extent) }
    })

    $commands = @(foreach ($c in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)) {
        $first = $c.CommandElements[0]
        $name = $c.GetCommandName()
        $nameSource = 'literal'
        if ([string]::IsNullOrEmpty($name)) {
            $name = Get-Folded $first
            $nameSource = if ($null -eq $name) { $null } else { 'folded' }
        }
        $elements = @(for ($i = 1; $i -lt $c.CommandElements.Count; $i++) {
            $el = $c.CommandElements[$i]
            if ($el -is [System.Management.Automation.Language.CommandParameterAst]) {
                [ordered]@{
                    kind         = 'parameter'
                    name         = $el.ParameterName
                    value        = (Get-Folded $el.Argument)
                    has_argument = ($null -ne $el.Argument)
                    text         = $el.Extent.Text
                    span         = (Get-Span $el.Extent)
                    variables    = (Get-VariableNames $el.Argument)
                }
            } else {
                [ordered]@{
                    kind         = 'value'
                    name         = $null
                    value        = (Get-Folded $el)
                    has_argument = $false
                    text         = $el.Extent.Text
                    span         = (Get-Span $el.Extent)
                    variables    = (Get-VariableNames $el)
                }
            }
        })
        $pipe = Get-PipelineInfo $c
        [ordered]@{
            name           = $name
            name_source    = $nameSource
            name_text      = $first.Extent.Text
            operator       = $c.InvocationOperator.ToString()
            text           = $c.Extent.Text
            span           = (Get-Span $c.Extent)
            elements       = $elements
            pipeline       = $pipe.span
            pipeline_index = $pipe.index
            name_choices   = (Get-NameChoices $c)
        }
    })

    $invocations = @(foreach ($m in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.InvokeMemberExpressionAst] }, $true)) {
        $typeName = $null
        if ($m.Expression -is [System.Management.Automation.Language.TypeExpressionAst]) {
            $typeName = Get-TypeName $m.Expression.TypeName
        }
        # A list keeps a $null for each argument that is not a literal, so positions hold.
        $argValues = New-Object System.Collections.Generic.List[object]
        foreach ($a in @($m.Arguments)) { if ($null -ne $a) { $argValues.Add((Get-Folded $a)) } }
        $vars = New-Object System.Collections.Generic.List[string]
        foreach ($a in @($m.Arguments)) { if ($null -ne $a) { foreach ($v in (Get-VariableNames $a)) { $vars.Add($v) } } }
        [ordered]@{
            member      = (Get-Folded $m.Member)
            static      = $m.Static
            type_name   = $typeName
            target_text = $m.Expression.Extent.Text
            arguments   = $argValues.ToArray()
            arg_count   = @($m.Arguments).Count
            variables   = $vars.ToArray()
            text        = $m.Extent.Text
            span        = (Get-Span $m.Extent)
        }
    })

    $strings = New-Object System.Collections.Generic.List[object]
    foreach ($s in $ast.FindAll({ param($n)
            $n -is [System.Management.Automation.Language.StringConstantExpressionAst] -or
            $n -is [System.Management.Automation.Language.ExpandableStringExpressionAst] }, $true)) {
        $strings.Add([ordered]@{ value = [string]$s.Value; span = (Get-Span $s.Extent); folded = $false })
    }
    foreach ($b in $ast.FindAll({ param($n)
            ($n -is [System.Management.Automation.Language.BinaryExpressionAst] -or
             $n -is [System.Management.Automation.Language.UnaryExpressionAst]) -and
            -not ($n.Parent -is [System.Management.Automation.Language.BinaryExpressionAst]) }, $true)) {
        $f = Get-Folded $b
        if ($null -ne $f) { $strings.Add([ordered]@{ value = $f; span = (Get-Span $b.Extent); folded = $true }) }
    }
    foreach ($t in $ast.FindAll({ param($n)
            $n -is [System.Management.Automation.Language.TypeExpressionAst] -or
            $n -is [System.Management.Automation.Language.TypeConstraintAst] }, $true)) {
        $strings.Add([ordered]@{ value = (Get-TypeName $t.TypeName); span = (Get-Span $t.Extent); folded = $false })
    }

    $assignments = @(foreach ($a in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] }, $true)) {
        if ($a.Left -is [System.Management.Automation.Language.VariableExpressionAst]) {
            [ordered]@{ variable = $a.Left.VariablePath.UserPath; value_span = (Get-Span $a.Right.Extent) }
        }
    })

    $functions = @(foreach ($f in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) { $f.Name })

    $usings = @(foreach ($u in $ast.UsingStatements) {
        [ordered]@{ kind = $u.UsingStatementKind.ToString(); text = $u.Extent.Text; span = (Get-Span $u.Extent) }
    })

    [ordered]@{
        id           = $doc.id
        parse_errors = $parseErrors
        commands     = $commands
        invocations  = $invocations
        strings      = $strings.ToArray()
        assignments  = $assignments
        functions    = $functions
        usings       = $usings
    }
}

$raw = [Console]::In.ReadToEnd()
$requestJson = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($raw.Trim()))
$request = ConvertFrom-Json -InputObject $requestJson

# One document that the walk cannot handle is reported as a parse error of that
# document, so it cannot stop the others from being analysed.
$documents = @(foreach ($doc in @($request.documents)) {
    try { ConvertTo-Document $doc }
    catch {
        [ordered]@{
            id           = $doc.id
            parse_errors = @([ordered]@{
                message  = "Bomb Squad could not read this code's syntax tree: $($_.Exception.Message)"
                error_id = 'BombSquadWalkFailed'
                span     = [ordered]@{ start = 0; end = 0; line = 1; column = 1; end_line = 1; end_column = 1 }
            })
            commands     = @()
            invocations  = @()
            strings      = @()
            assignments  = @()
            functions    = @()
            usings       = @()
        }
    }
})
$response = [ordered]@{
    parser    = [ordered]@{
        edition = [string]$PSVersionTable.PSEdition
        version = $PSVersionTable.PSVersion.ToString()
    }
    documents = $documents
}
$json = ConvertTo-Json -InputObject $response -Depth 12 -Compress
[Console]::Out.Write([Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($json)))
