# joker-python-dmapi
Python API and scripts for Joker.com DMAPI

## Usage with lego

You can use this simple module to write your own scripts or as a DNS-01 exec resolver for [lego](https://github.com/go-acme/lego)

```shell
$ export JOKER_API_KEY=....
$ export EXEC_PATH=~/.lego/joker.py
$ lego -m admin@example.com -a --dns exec -d '*.example.com' run
```
