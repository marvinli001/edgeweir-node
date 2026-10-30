# hello-header

Example node extension: a greeting response header, the rule field `ext.hello-header.greeted`, a log field, a counter, the endpoint `/.edgeweir/ext/hello-header/ping` and an optional script injected into HTML. The end-to-end tests use it.

```bash
edgeweir-node extension pack examples/extensions/hello-header -o hello-header-1.0.0.ewx
edgeweir-node extension sign --key publisher.jwk hello-header-1.0.0.ewx
```
