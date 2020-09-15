# MITMProxy GBP Utils

## Scripts

### Rewrite
Given rewrite-router.yaml file contains on key the url which we will mock. The mocks are located in responses directory.
```
http://gbptest.com/testing: test_ok
```
In the example all GET requests to url with be rewrited to test_ok.json located on responses directory. Status, Body and headers can be updated.

#### Run MITMProxy rewrite script
```
mitmproxy --listen-port 8081 -s rewrite.py
```


### More Scripts soon! ;)
