# SSH stdio transport

The transport can run entirely inside an SSH channel. In this mode the source
does not dial `peer`, and the sink does not bind a TCP listener.

```sh
agentpantry source --stdio | ssh sink.example agentpantry sink --stdio
```

Both endpoints still need matching config files and the same `psk.key`.
Run `agentpantry doctor --no-net` on the source when you only use stdio.
