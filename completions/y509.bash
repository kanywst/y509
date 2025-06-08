# y509 bash completion script

_y509() {
    local cur prev words cword
    _init_completion || return

    # Define options
    local opts="-h --help -v --version"
    
    case $prev in
        -h|--help|-v|--version)
            return
            ;;
    esac

    if [[ $cur == -* ]]; then
        COMPREPLY=( $(compgen -W "${opts}" -- "$cur") )
        return
    fi

    # Complete with files with .pem, .crt, .cert, .der extensions
    _filedir '@(pem|crt|cert|der)'
}

complete -F _y509 y509
