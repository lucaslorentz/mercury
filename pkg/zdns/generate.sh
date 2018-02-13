#!/usr/bin/env sh
echo "package zdns\n\nvar tmproot = \`" > dns_forward_root.go
curl http://www.internic.net/domain/named.root >> dns_forward_root.go
echo "\`" >> dns_forward_root.go
