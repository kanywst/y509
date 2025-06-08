#compdef y509

_y509() {
    local -a opts
    opts=(
        '(-h --help)'{-h,--help}'[Show help message and exit]'
        '(-v --version)'{-v,--version}'[Show version information and exit]'
    )

    _arguments -s \
        "${opts[@]}" \
        '*:certificate file:_files -g "*.{pem,crt,cert,der}"'
}

_y509 "$@"
