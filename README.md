# ya-runtime-outbound-gateway

Outbound Gateway runtime allows Requestor to route his network traffic through Provider.
In the future it could be seen as general network gateway for all Providers in Golem VPN network
setup by Requestor.


## Setup Provider

This command will build runtime, install it in yagna directories and setup Provider presets:
`./setup/install.sh`

You can run `./setup/install-runtime.sh` if your have already preapred Provider configuration,
but need to rebuild and replace runtime binaries.


## Run example

Yapapi example can be found here:
https://github.com/golemfactory/yapapi/pull/1101

Run:
```
export YAGNA_APPKEY={your-appkey-here}
poetry run python3 outbound-gateway.py
```

## Market negotiations

More about properties exposed by Runtime and how to negotiate Agreement can be found here: https://github.com/golemfactory/yagna/wiki/Outbound-Gateway#market-negotiations
