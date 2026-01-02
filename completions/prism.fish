# Fish completion script for Prism
# Install: Copy to ~/.config/fish/completions/prism.fish

# Disable file completion by default
complete -c prism -f

# Commands
complete -c prism -n __fish_use_subcommand -a run -d 'Start the Prism proxy server'
complete -c prism -n __fish_use_subcommand -a validate -d 'Validate configuration file'
complete -c prism -n __fish_use_subcommand -a check -d 'Check configuration and exit'
complete -c prism -n __fish_use_subcommand -a version -d 'Show version information'
complete -c prism -n __fish_use_subcommand -a help -d 'Show help information'

# Global options
complete -c prism -s c -l config -d 'Configuration file path' -r -F
complete -c prism -s w -l watch -d 'Watch configuration file for changes'
complete -c prism -s v -l version -d 'Show version'
complete -c prism -s h -l help -d 'Show help'
complete -c prism -l log-level -d 'Set log level' -xa 'trace debug info warn error'
complete -c prism -l log-format -d 'Set log format' -xa 'json text pretty'
complete -c prism -l admin-addr -d 'Admin API address' -x
complete -c prism -l metrics-addr -d 'Metrics endpoint address' -x

# Subcommand: run
complete -c prism -n '__fish_seen_subcommand_from run' -s c -l config -d 'Configuration file' -r -F
complete -c prism -n '__fish_seen_subcommand_from run' -s w -l watch -d 'Watch for config changes'

# Subcommand: validate
complete -c prism -n '__fish_seen_subcommand_from validate' -s c -l config -d 'Configuration file' -r -F

# Subcommand: check
complete -c prism -n '__fish_seen_subcommand_from check' -s c -l config -d 'Configuration file' -r -F

# Config file completion (yaml/toml files)
complete -c prism -n '__fish_seen_subcommand_from run validate check' -a '(__fish_complete_suffix .yaml .yml .toml)'
