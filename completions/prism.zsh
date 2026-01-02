#compdef prism

# Zsh completion script for Prism
# Install: Copy to a directory in your $fpath (e.g., ~/.zsh/completions/)
# Then add: autoload -Uz compinit && compinit

_prism() {
    local -a commands
    local -a options

    commands=(
        'run:Start the Prism proxy server'
        'validate:Validate configuration file'
        'check:Check configuration and exit'
        'version:Show version information'
        'help:Show help information'
    )

    options=(
        '(-c --config)'{-c,--config}'[Configuration file path]:config file:_files -g "*.{yaml,yml,toml}"'
        '(-w --watch)'{-w,--watch}'[Watch configuration file for changes]'
        '(-v --version)'{-v,--version}'[Show version]'
        '(-h --help)'{-h,--help}'[Show help]'
        '--log-level[Set log level]:level:(trace debug info warn error)'
        '--log-format[Set log format]:format:(json text pretty)'
        '--admin-addr[Admin API address]:address:'
        '--metrics-addr[Metrics endpoint address]:address:'
    )

    _arguments -s \
        $options \
        '1:command:->commands' \
        '*::arg:->args'

    case "$state" in
        commands)
            _describe -t commands 'prism commands' commands
            ;;
        args)
            case $words[1] in
                run)
                    _arguments \
                        '(-c --config)'{-c,--config}'[Configuration file]:config:_files -g "*.{yaml,yml,toml}"' \
                        '(-w --watch)'{-w,--watch}'[Watch for config changes]'
                    ;;
                validate|check)
                    _arguments \
                        '(-c --config)'{-c,--config}'[Configuration file]:config:_files -g "*.{yaml,yml,toml}"'
                    ;;
            esac
            ;;
    esac
}

_prism "$@"
