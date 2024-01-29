# Readme

The goal of this plugin is to provide a reliable way of detecting altered requests within you
own network. Don't think of it as an extra layer of security, it's just a way too see if the request was
changed while floating inside your own network.

### config local

```yaml
  middlewares:
    my-plugin:
      plugin:
        example:
          signatureHeaderName: "X-Test-Sign" # here goes the signature
          constructHeaderName: "X-Test-Construct" # here goes the order pre-hashed
          timeHeaderName: "X-Test-Time" # will be added to the hash as well
          pathRegex:
            - "^/api/v1"
          additionalHeaders:
            X-Add-Test1: "ImAValue"
            X-Add-Test2: "ImAValueToo"
          requiredHeaders: # you will fail if these are missing
            rq1: "Accept"
            rq2: "Referer"
          optionalHeaders: # you will not fail if these are missing
            op1: "Content-Type"
            op2: "Content-Length"
            op3: "X-Add-Test1"
          maxHashableContentLength: "1000" # x<0 all, x==0 none, x>0 ]0,x]
          hashableContentTypes: # if not specified, all are accepted
            - "text/csv"
            - "application/x-www-form-urlencoded"
          keyName: "superduper" # this is an env var, must be present
          keyType: "rsa/ed25519"
          keyValue: "base64url-safe encoded private key"
          rsaSignatureAlgo: "pcks1v15/pss"
          errorStatus: 500
          errorMessage: true
```

this is an example for local development

`signatureHeaderName`: name of the header, where the signature goes to, can be ommited.
defaults to "X-Test-Signature"

`constructHeaderName`: name of the header, where the construct-string goes to, can be ommited.
defaults to "X-Test-Construct"

`timeHeaderName`: if set, creates an [time.RFC3339Nano](https://pkg.go.dev/time#pkg-constants) timestamp(UTC forced),
will be part of signature and construct. can be omitted.

`requiredHeaders`: if set, it will fail with `errorStatus`-Code and error message if allowed by `errorMessage`.
can be omitted.

`optionalHeaders`: if requested header is missing, will skip them silently.
can be omitted.

`maxHashableContentLength`: you can set is, to reduce the mem-consumption. `-1` will allow all
lengths, `0` will ignore all bodys and `x>0` will result in `]0,x]`. can be omitted, defaults to
`-1`

`hashableContentTypes`: if set, it will only add body to hash, when `Content-Type` matches.
see [MIME-Types](https://www.iana.org/assignments/media-types/media-types.xhtml).
if omitted, all will be accepted for hashing.

`keyName`: env var for the private key. if omitted, `keyValue` must be set

`keyType`: `rsa` or `ed25519` can be set

`keyValue`: base64 urlsafe encoded private key, set it on deployment. ask your devops

`rSASignatureAlgo`: choose between `pcks1v15` and `pss`. can be omitted, if `keyType` is `ed25519`

`errorStatus`: choose a statuscode, defaults to `400`

`errorMessage`: if error-message will be added, can be omitted and defaults to true

## Construct-String

all possible shorts and their translation
and in the `Header` it looks like this `X-Test-Construct: th,m,h,p,d1,d11,eb`

recreate the hash on the receiving end and validate the signature

```json
{
  "th": "custom time header",
  "m": "http-method",
  "p": "path"
}
```

```json
{
  "ib": "ignored body",
  "nb": "no body present",
  "ub": "stream or smth, unknown Content-Length",
  "sb": "skipped body(hashable contents)",
  "wb": "with body(the only, where you need to hash)",
  "eb": "enormous body, exceeds maxHashableContentLength"
}

```

#### keyfile to env var

```shell
export superduper=$(cat key-file)
```

#### traefik startup local

```shell
./traefik --configfile traefik-sigdemo.yaml
```

```shell
openssl genpkey -algorithm ed25519 -out ed25519.pem
```

```shell
openssl pkey -in ed25519.pem -pubout -out ed25519.pub
```

```shell
ssh-keygen -t rsa -b 4096 -m PEM -f key-file
```

```shell
openssl rsa -in key-file -pubout -outform PEM -out key-file.pub
```