# Bash completion script for Prism
# Install: source this file or copy to /etc/bash_completion.d/prism

_prism_completions() {
    local cur prev opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    # Main commands/options
    opts="--config --watch --validate --check --version --help -c -w -v -h"

    # Subcommands
    local commands="run validate check version help"

    case "${prev}" in
        -c|--config)
            # Complete with yaml/toml files
            COMPREPLY=( $(compgen -f -X '!*.@(yaml|yml|toml)' -- "${cur}") )
            return 0
            ;;
        prism)
            COMPREPLY=( $(compgen -W "${commands}" -- "${cur}") )
            return 0
            ;;
    esac

    # Handle flags that take arguments
    case "${cur}" in
        -*)
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
    esac

    # Default to files if nothing else matches
    COMPREPLY=( $(compgen -f -- "${cur}") )
}

complete -F _prism_completions prism
