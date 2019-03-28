#!/bin/sh

[ -n "$SSH_AUTH_INFO_0" ] && /opt/nintendohomebrew/bin/nhctl notify-session $PAM_USER $PAM_TYPE "$SSH_AUTH_INFO_0"
