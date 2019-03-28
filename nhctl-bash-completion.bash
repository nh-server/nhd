#!/bin/bash

# based on the apt and apt-get completion scripts
_nhctl()
{
    local cur prev words cword
    _init_completion -n = || return
    COMPREPLY=()

    local special i
    for (( i=0; i < ${#words[@]}-1; i++ )); do
        if [[ ${words[i]} == @(restart|update|status|add-user|del-user|disable-user|enable-user|notify-reboot|list-services) ]]; then
            special=${words[i]}
            break
        fi
    done

    if [[ "$cur" == -* ]]; then
        case $special in
            restart)
                COMPREPLY=( $( compgen -W '-f --force' -- "$cur" ) )
                ;;
            add-user)
                COMPREPLY=( $( compgen -W '-u -k -d -i
                  --username --ssh-public-key --discord-name --discord-id' -- "$cur" ) )
                ;;
            del-user)
                COMPREPLY=( $( compgen -W '-u --username --remove-home' -- "$cur" ) )
                ;;
            disable-user)
                COMPREPLY=( $( compgen -W '-u --username' -- "$cur" ) )
                ;;
            enable-user)
                COMPREPLY=( $( compgen -W '-u --username' -- "$cur" ) )
                ;;
            notify-reboot)
                COMPREPLY=( $( compgen -W '-l -m --list --message' -- "$cur" ) )
                ;;
            *)
                COMPREPLY=()
                ;;
        esac
        return
    fi

    if [[ -n $special ]]; then
        case $special in
            restart|update|status)
                COMPREPLY=( $( compgen -W '$(nhctl -q list-services)' -- "$cur" ) )
                ;;
            add-user)
                case $prev in
                    -k|--ssh-public-key)
                        _filedir pub
                        return
                        ;;
                    -u|-d|-i|--username|--discord-name|--discord-id)
                        COMPREPLY=()
                        return
                        ;;
                    *)
                        COMPREPLY=( $( compgen -W '-u -k -d -i
                          --username --ssh-public-key --discord-name --discord-id' -- "$cur" ) )
                        ;;
                esac
                ;;
            del-user)
                case $prev in
                    -u|--username)
                        COMPREPLY=( $( compgen -W "$(ls /opt/nintendohomebrew/etc/nhd/discord-id)" -- "$cur" ) )
                        ;;
                    *)
                        COMPREPLY=( $( compgen -W '-u --username --remove-home' -- "$cur") )
                        ;;
                esac
                ;;
            disable-user)
                case $prev in
                    -u|--username)
                        COMPREPLY=( $( compgen -W "$(ls /opt/nintendohomebrew/etc/nhd/discord-id)" -- "$cur" ) )
                        ;;
                    *)
                        COMPREPLY=( $( compgen -W '-u --username' -- "$cur") )
                        ;;
                esac
                ;;
            enable-user)
                case $prev in
                    -u|--username)
                        COMPREPLY=( $( compgen -W "$(ls /opt/nintendohomebrew/etc/nhd/discord-id)" -- "$cur" ) )
                        ;;
                    *)
                        COMPREPLY=( $( compgen -W '-u --username' -- "$cur") )
                        ;;
                esac
                ;;
            notify-reboot)
                case $prev in
                    -m|--message)
                        COMPREPLY=( $( compgen -W "$(ls /opt/nintendo/etc/nhd/notify-reboot)" -- "$cur" ) )
                        ;;
                    *)
                        COMPREPLY=( $( compgen -W '-l -m --list --message' -- "$cur" ) )
                        ;;
                esac
                ;;
            *)
                COMPREPLY=()
                ;;
        esac
        return
    fi

    if [[ "$cur" == -* ]]; then
        COMPREPLY=( $( compgen -W '-h -q -v --help --quiet --verbose' -- "$cur" ) )
    else
        COMPREPLY=( $( compgen -W 'restart update status add-user del-user disable-user enable-user notify-reboot list-services' -- "$cur" ) )
    fi

} &&

complete -F _nhctl nhctl
