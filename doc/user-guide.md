# User Guide

## Introduction

_buddy-auth_ is a module that provides authentication and authorization for Ring
and Ring-based web applications.


### Project Maturity

_buddy-auth_ is a stable library. This is a maintenance fork of
[funcool/buddy-auth](https://github.com/funcool/buddy-auth), published as
`net.clojars.savya/buddy-auth`.


### Install

deps.edn:

```clojure
net.clojars.savya/buddy-auth {:mvn/version "4.0.2"}
```

Leiningen:

```clojure
[net.clojars.savya/buddy-auth "4.0.2"]
```

Use this package with *jdk>=8*.


## Authentication

### Introduction

The buddy approach to authentication is explicit. Unlike most authentication
libraries, _buddy_ keeps authentication separate from authorization.

Authentication uses a pluggable backend. Use a built-in backend, or implement a
new backend. These are the built-in backends:

| Backend name  | Namespace                      |
|---------------|--------------------------------|
| Http Basic    | `buddy.auth.backends/basic`    |
| Session       | `buddy.auth.backends/session`  |
| Token         | `buddy.auth.backends/token`    |
| Signed JWT    | `buddy.auth.backends/jws`      |
| Encrypted JWT | `buddy.auth.backends/jwe`      |
| JWKS          | `buddy.auth.backends/jwks`     |

If a built-in backend does not meet your needs, implement your own backend. You
can use it with the _buddy-auth_ middleware.

The authentication process has two steps:

1. *parse*: this step reads the request and gets authentication data, such as
   an `Authorization` header or URL parameters.
2. *auth*: this step uses the data from the parse step to authenticate the
   request, such as a database lookup, a self-contained jws/jwe token, or a
   session key.

This step raises no exceptions. The authentication process determines if a
request is anonymous or authenticated.

### Backends

#### Http-Basic

The HTTP Basic authentication backend is simple but insecure. It can help you
learn how _buddy-auth_ authentication works.

```clojure
(require '[ring.util.response :refer (response)])

;; Simple ring handler. This can also be a compojure router handler
;; or anything else compatible with ring middleware.

(defn my-handler
  [request]
  (if (:identity request)
    (response (format "Hello %s" (:identity request)))
    (response "Hello Anonymous")))
```

To check if a request is authenticated, look at the `:identity` key. The
request is authenticated if the key exists and contains a logical `true` value.
This value is different from `nil` and `false`.

Set up the authentication backend like this:

```clojure
(require '[buddy.auth.backends :as backends])

(defn my-authfn
  [request authdata]
  (let [username (:username authdata)
        password (:password authdata)]
    username))

(def backend (backends/basic {:realm "MyApi"
                              :authfn my-authfn}))
```

The `authfn` does the second step of authentication. It receives the parsed
auth data from the request. It must return a logical true value: a user id, a
user instance, or something different to `nil` and `false`. _buddy-auth_ calls
it only if step 1 (parse) returns something.

Then wrap your Ring handler with the authentication and authorization middleware:

```clojure
(require '[buddy.auth.middleware :refer [wrap-authentication
                                         wrap-authorization]])

;; Define the main handler with *app* name wrapping it
;; with authentication middleware using an instance of the
;; just created http-basic backend.

;; Define app var with handler wrapped with _buddy-auth_'s authentication
;; and authorization middleware using the previously defined backend.

(def app (-> my-handler
             (wrap-authentication backend)
             (wrap-authorization backend)))
```

The authentication process runs for all requests that reach `my-handler`.


#### Session

The session backend uses Ring session support.

This backend checks the `:identity` keyword in the session. If it exists and is
a logical true, the backend puts it in the request under the `:identity` property.

```clojure
(require '[buddy.auth.backends :as backends])

;; Create an instance
(def backend (backends/session))

;; Wrap the ring handler.
(def app (-> my-handler
             (wrap-authentication backend)))
```


#### Token

This backend uses tokens to authenticate the user. It behaves like the
basic-auth backend, but it authenticates with a token instead of credentials.

This is an example:

```clojure
(require '[buddy.auth.backends :as backends])

;; Define a in-memory relation between tokens and users:
(def tokens {:2f904e245c1f5 :admin
             :45c1f5e3f05d0 :foouser})

;; Define an authfn, function with the responsibility
;; to authenticate the incoming token and return an
;; identity instance

(defn my-authfn
  [request token]
  (let [token (keyword token)]
    (get tokens token nil)))

;; Create an instance
(def backend (backends/token {:authfn my-authfn}))

;; Wrap the ring handler.
(def app (-> my-handler
             (wrap-authentication backend)))
```

This backend parses the "Authorization" header and extracts the token. If it
extracts a token, it calls the `authfn` with that token.

```clojure
Authorization: Token 45c1f5e3f05d0
```

The `authfn` must return the value that _buddy-auth_ puts in the `:identity`
key of the request.

_buddy_ only parses the request and calls the user function to authenticate it.
You must build and store the tokens.

The `Bearer` Authorization scheme is parsed case-insensitively. To emit an RFC 6750
`WWW-Authenticate` Bearer challenge on default 401 and 403 responses, set
`:bearer-challenge true`. The option is disabled by default, and custom
`:unauthorized-handler` functions are returned unchanged.

You can see a complete example of this backend <<example-token,here>>.


#### Signed JWT

This backend uses signed, self contained tokens to authenticate the user.

It behaves like the _Token_ backend above. This backend needs no user-defined
logic to validate the tokens because each token is self-contained.

This token mechanism provides stateless authentication. The server does not
store the token or related data. The token contains the data for authentication.

This is an example:

```
(require '[buddy.auth.backends :as backends])
(require '[buddy.auth.middleware :refer (wrap-authentication)])

(def secret "mysecret")
(def backend (backends/jws {:secret secret}))

;; and wrap your ring application with
;; the authentication middleware

(def app (-> your-ring-app
             (wrap-authentication backend)))
```

Your ring application must also have a login endpoint. This endpoint generates
the valid tokens:

```clojure
(require '[buddy.sign.jwt :as jwt])
(require '[cheshire.core :as json])

(defn login-handler
  [request]
  (let [data (:form-params request)
        user (find-user (:username data)   ;; (implementation ommited)
                        (:password data))
        token (jwt/sign {:user (:id user)} secret)]
    {:status 200
     :body (json/encode {:token token})
     :headers {:content-type "application/json"}}))
```

For more information about jwt, see the
link:https://funcool.github.io/buddy-sign/latest/#jwt[buddy-sign] documentation.

These resources give more information about stateless authentication:

- http://lucumr.pocoo.org/2013/11/17/my-favorite-database/
- http://www.niwi.nz/2014/06/07/stateless-authentication-with-api-rest/


#### Encrypted JWT

This backend is similar to the signed JWT backend.

This backend uses JWE (JSON Web Encryption) instead of JWS (JSON Web Signature).
It encrypts the token content instead of only signing it. Use it when a token
contains user data that must remain private.

This example uses jwe with an asymmetric encryption algorithm:

```clojure
(require '[buddy.auth.backends :as backends])
(require '[buddy.auth.middleware :refer (wrap-authentication)])
(require '[buddy.sign.jwe :as jwe])
(require '[buddy.core.keys :as keys])

(def pubkey (keys/public-key "pubkey.pem"))
(def privkey (keys/private-key "privkey.pem"))

(def backend
  (backends/jwe {:secret privkey
                 :options {:alg :rsa-oaep
                           :enc :a128-hs256}}))

;; and wrap your ring application with
;; the authentication middleware

(def app (-> your-ring-app
             (wrap-authentication backend)))
```

The login endpoint can look like this:

```clojure
(require '[buddy.sign.jwt :as jwt])
(require '[cheshire.core :as json])

(defn login-handler
  [request]
  (let [data (:form-params request)
        user (find-user (:username data)   ;; (implementation ommited)
                        (:password data))
        token (jwt/encrypt {:user (:id user)} pubkey
                           {:alg :rsa-oaep :enc :a128-hs256})]
    {:status 200
     :body (json/encode {:token token})
     :headers {:content-type "application/json"})))
```

To use an asymmetric encryption algorithm, you need a private and public key pair.
Use *openssl* to generate a key pair. See this
link:https://funcool.github.io/buddy-sign/latest/#generate-keypairs[FAQ entry].

#### JWKS

The signed and encrypted JWT backends above verify tokens with a local key. The
JWKS backend validates signed JWTs with a JWK Set. An identity provider usually
publishes this set at a remote JWKS endpoint. Providers include Auth0, Google,
Okta, and Keycloak. The provider signs tokens with rotating keys and publishes
the public keys at a JWKS URL. Your service fetches and caches the keys.

This backend uses [jose-clj](https://github.com/jsavyasachi/jose-clj), which uses
Nimbus JOSE+JWT. `jose-clj` is an *optional* dependency and is not transitive.
Add it to your project to use this backend. Calling `backends/jwks` without it
throws an error:

```clojure
net.clojars.savya/jose-clj {:mvn/version "0.5.0"}   ; deps.edn
[net.clojars.savya/jose-clj "0.5.0"]                ; Leiningen
```

It requires JDK 11+ through jose-clj. By default, the backend reads a bearer
token from the `Authorization` header with the `Bearer` scheme.

```clojure
(require '[buddy.auth.backends :as backends])
(require '[buddy.auth.middleware :refer (wrap-authentication)])

;; validate against a provider's JWKS endpoint, with standard claim checks
(def backend
  (backends/jwks {:jwks-url "https://accounts.google.com/.well-known/jwks.json"
                  :options {:iss "https://accounts.google.com"
                            :aud "your-client-id"
                            :clock-skew 60
                            :required [:sub]}}))

(def app (-> your-ring-app
             (wrap-authentication backend)))
```

The backend fetches the key set once and caches it. The underlying source handles
the cache and its refresh. On success, the request's `:identity` is the validated
claims map. A verification or claim check can fail because of a bad signature,
unknown key ID, expiry, issuer or audience mismatch, or missing required claim.
Such a failure leaves the request unauthenticated. Pass an `:on-error` hook to
get the cause.

Options:

- `:jwks-url` - URL of a JWKS endpoint (mutually exclusive with `:source`).
- `:source` - a prebuilt `jose.jwks` source (`remote-source` or `local-source`).
  Use it for tests or custom fetches.
- `:jwks-opts` - map passed to `jose.jwks/remote-source` (`:cache-ttl-ms`,
  `:connect-timeout-ms`, `:read-timeout-ms`, `:rate-limit-ms`).
- `:options` - claim validation passed to jose-clj (`:iss`, `:aud`, `:clock-skew`,
  `:required`).
- `:token-name` - the Authorization scheme, `"Bearer"` by default.
- `:bearer-challenge` - when true, add an RFC 6750 `WWW-Authenticate: Bearer`
  challenge with an error and description to default 401/403 responses.
- `:authfn` - transforms validated claims into the request identity.

### OIDC provider discovery

For providers that publish OpenID Connect discovery metadata, use
`backends/oidc` with the issuer URL. It fetches the issuer's
`/.well-known/openid-configuration`, reads `jwks_uri`, and then uses the JWKS
backend for signature and claim validation:

```clojure
(backends/oidc {:issuer "https://accounts.google.com"
                :audience "your-client-id"
                :nonce expected-nonce
                :options {:algs #{:rs256}}})
```

The configured issuer and audience are validated as standard JWT claims. When
the token contains multiple audiences, `azp` must match the configured
audience. A configured nonce must also match the token's `nonce` claim.
`backends/discover-jwks-url` is available when only the discovered JWKS URL is
needed. OIDC discovery uses the JDK HTTP client and does not add a dependency.
- `:on-error` - `(fn [request exception] ...)` runs when validation fails.


## Authorization

Authorization is the second part of the authentication process.

The authorization system has two parts: generic authorization and access rules.

Generic authorization raises an unauthorized exception for an unauthorized
request. Access rules attach rules to a handler or a _URI_. These rules determine
if a request is authorized.


### Exception-Based

This authorization method wraps code in a try/catch block for specific exceptions.
When it catches an unauthorized exception, it runs a function or raises the
exception again.

Use this method to define middleware or decorators with custom authorization
logic. Use `throw-unauthorized` to raise an unauthorized exception.

```clojure
(require '[buddy.auth :refer [authenticated? throw-unauthorized]])
(require '[ring.util.response :refer (response redirect)])

(defn home-controller
  [request]
  (when (not (authenticated? request))
    (throw-unauthorized {:message "Not authorized"}))
  (response "Hello World"))
```

Authorization also uses pluggable backends.

All built-in backends implement the authorization protocol with default behavior.
Pass `:unauthorized-handler` to the backend constructor to change this behavior:

```clojure
(require '[buddy.auth.backends :as backends])
(require '[buddy.auth.middleware :refer [wrap-authentication wrap-authorization]])

;; Simple self defined handler for unauthorized requests.
(defn my-unauthorized-handler
  [request metadata]
  (-> (response "Unauthorized request")
      (assoc :status 403)))

(def backend (backends/basic
              {:realm "API"
               :authfn my-auth-fn
               :unauthorized-handler my-unauthorized-handler}))

(def app (-> your-handler
             (wrap-authentication backend)
             (wrap-authorization backend)))
```


### Access Rules

The access rules system is part of authorization. It matches a URL to access rule
logic.

Access rules are an ordered list of URL-to-rule-handler mappings. Use
link:https://github.com/weavejester/clout[clout] URL matching syntax or regular
expressions.

```clojure
[{:uri "/foo"
  :handler user-access}
```

```clojure
[{:uris ["/foo" "/bar"]
  :handler user-access}
```

```clojure
[{:pattern #"^/foo$"
  :handler user-access}
```

An access rule can also match HTTP methods with the *:request-method* option.
*:request-method* can be a keyword or a set of keywords.

This access rule matches only GET requests:

```clojure
[{:uri "/foo"
  :handler user-access
  :request-method :get}
```


#### Rules Handlers

The rule handler is a plain function that accepts a request. It must return
`accessrules/success` or `accessrules/error`.

`success` marks a handler that passes validation. `error` marks a handler that
does not pass validation. A handler can return error messages or a Ring response
instead of a Boolean value.

This is an example of a rule handler:

```clojure
(require '[buddy.auth.accessrules :refer (success error)])

(defn authenticated-user
  [request]
  (if (:identity request)
    true
    (error "Only authenticated users allowed")))
```

These values are success marks: *true* and *success* instances. These values are
error marks: *nil*, *false*, and *error* instances. An error instance can contain
an error message or a Ring response hash map.

A rule handler can combine several rule handlers with logical operators.

```clojure
{:and [authenticated-user other-handler]}
{:or [authenticated-user other-handler]}

;; Logical expressions can be nested as deep as you wish
;; with hypotetical rule handlers with self descriptive name.
{:or [should-be-admin
      {:and [should-be-safe
             should-be-authenticated]}]}}
```

This example uses a combined rule handler in an access rules list:

```clojure
[{:pattern #"^/foo$"
  :handler {:and [authenticated-user admin-user]}}]
```

With *clout* syntax, a request in a rule handler contains `:match-params` with
the URI parameters that clout matches.


#### Usage

You can define and use access rules and rule handlers in Ring applications.

_buddy-auth_ provides two methods:

* Use _wrap-access-rules_ middleware.
* Use a _restrict_ decorator to assign rule handlers to a Ring handler.

These examples show these methods:

```clojure
;; Rules handlers used on this example are ommited for code clarity
;; Each handler represents authorization logic indicated by its name.

(def rules [{:pattern #"^/admin/.*"
             :handler {:or [admin-access operator-access]}}
            {:pattern #"^/login$"
             :handler any-access}
            {:pattern #"^/.*"
             :handler authenticated-access}])

;; Define default behavior for not authorized requests
;;
;; This function works like a default ring compatible handler
;; and should implement the default behavior for requests
;; which are not authorized by any defined rule

(defn on-error
  [request value]
  {:status 403
   :headers {}
   :body "Not authorized"})

;; Wrap the handler with access rules (and run with jetty as example)
(defn -main
  [& args]
  (let [options {:rules rules :on-error on-error}
        app     (wrap-access-rules your-app-handler options)]
    (run-jetty app {:port 3000})))
```

If a request URI does not match a regular expression, the default policy applies.
The default policy in _buddy-auth_ is *allow*. Set `:policy` to `:reject` to
change the default behavior.

Instead of a global _on-error_ handler, set behavior on an access rule. You can
also use the _:redirect_ option to redirect a user to a URL.

```clojure
(def rules [{:pattern #"^/admin/.*"
             :handler {:or [admin-access operator-access]}
             :redirect "/notauthorized"}
            {:pattern #"^/login$"
             :handler any-access}
            {:pattern #"^/.*"
             :handler authenticated-access
             :on-error (fn [req _] (response "Not authorized ;)"))}])
```

The access rule options take precedence over the global options.

Use the `restrict` decorator when you apply rules to specific Ring views or
handlers without an external rules list:

```clojure
(require '[buddy.auth.accessrules :refer [restrict]])

(defn home-controller
  [request]
  {:body "Hello World" :status 200})

(defroutes app
  (GET "/" [] (restrict home-controller {:handler should-be-authenticated
                                         :on-error on-error}))
```


## Examples

### Http Basic Auth Example

This example shows how to set up HTTP Basic authentication in a simple Ring-based
application.

Run these commands:

```
git clone https://github.com/funcool/buddy-auth.git
cd ./buddy-auth/
lein with-profile +httpbasic-example run
```

Open http://localhost:3000/ in a browser.

The credentials are: `admin` / `secret` and `test` / `secret`.

The example code is here:
https://github.com/funcool/buddy-auth/tree/master/examples/httpbasic


### Session Auth Example

This example shows how to set up session-based authentication in a simple
Ring-based application.

Run these commands:

```
git clone https://github.com/funcool/buddy-auth.git
cd ./buddy-auth/
lein with-profile +session-example run
```

Open http://localhost:3000/ in a browser.

The credentials are: `admin` / `secret` and `test` / `secret`.

The example code is here:
https://github.com/funcool/buddy-auth/tree/master/examples/session


### Token Auth Example

This example shows how to set up token-based authentication in a simple Ring-based
application.

Run these commands:

```
git clone https://github.com/funcool/buddy-auth.git
cd ./buddy-auth/
lein with-profile +token-example run
```

Use *curl* with the authentication example:

```
$ curl -v -X POST -H "Content-Type: application/json" -d '{"username": "admin", "password": "secret"}' http://localhost:3000/login
* Connected to localhost (::1) port 3000 (#0)
> POST /login HTTP/1.1
> Host: localhost:3000
> User-Agent: curl/7.46.0
> Accept: */*
> Content-Type: application/json
> Content-Length: 43
>
* upload completely sent off: 43 out of 43 bytes
< HTTP/1.1 200 OK
< Date: Mon, 04 Jan 2016 13:54:02 GMT
< Content-Type: application/json; charset=utf-8
< Content-Length: 44
< Server: Jetty(9.2.10.v20150310)
<
* Connection #0 to host localhost left intact
{"token":"fe562338bf1604bd175722e32a4d7115"}
```

```
$ curl -v -X GET -H "Content-Type: application/json" -H "Authorization: Token fe562338bf1604bd175722e32a4d7115" http://localhost:3000/
* Connected to localhost (::1) port 3000 (#0)
> GET / HTTP/1.1
> Host: localhost:3000
> User-Agent: curl/7.46.0
> Accept: */*
> Content-Type: application/json
> Authorization: Token fe562338bf1604bd175722e32a4d7115
>
< HTTP/1.1 200 OK
< Date: Mon, 04 Jan 2016 13:54:40 GMT
< Content-Type: application/json; charset=utf-8
< Content-Length: 55
< Server: Jetty(9.2.10.v20150310)
<
* Connection #0 to host localhost left intact
{"status":"Logged","message":"hello logged user:admin"}
```

The example code is here:
https://github.com/funcool/buddy-auth/tree/master/examples/token


### JWE Token Auth Example

This example shows how to set up JWE stateless token-based authentication in a
simple Ring-based application.

Run these commands:

```
git clone https://github.com/funcool/buddy-auth.git
cd ./buddy-auth/
lein with-profile +jwe-example run
```

Use *curl* with the authentication example:

```
$ curl -v -X POST -H "Content-Type: application/json" -d '{"username": "admin", "password": "secret"}' http://localhost:3000/login
* Connected to localhost (::1) port 3000 (#0)
> POST /login HTTP/1.1
> Host: localhost:3000
> User-Agent: curl/7.46.0
> Accept: */*
> Content-Type: application/json
> Content-Length: 43
>
* upload completely sent off: 43 out of 43 bytes
< HTTP/1.1 200 OK
< Date: Mon, 04 Jan 2016 13:52:11 GMT
< Content-Type: application/json; charset=utf-8
< Content-Length: 189
< Server: Jetty(9.2.10.v20150310)
<
* Connection #0 to host localhost left intact
{"token":"eyJhbGciOiJBMjU2S1ciLCJ0eXAiOiJKV1MiLCJlbmMiOiJBMTI4R0NNIn0.Q672y_lD3bOU_qm5U0RDKS-YszRHfkFu.vDZaAJPz8uL5q1A4.LonJtHZMA_Ty53YBmr1zpE7-SIbTJgVgme--Tjj25dHN.goYEyM3JZgYlbARo8CDk0g"}
```

Send an authenticated request with the token:

```
$ curl -v -X GET -H "Content-Type: application/json" -H "Authorization: Token eyJhbGciOiJBMjU2S1ciLCJ0eXAiOiJKV1MiLCJlbmMiOiJBMTI4R0NNIn0.Q672y_lD3bOU_qm5U0RDKS-YszRHfkFu.vDZaAJPz8uL5q1A4.LonJtHZMA_Ty53YBmr1zpE7-SIbTJgVgme--Tjj25dHN.goYEyM3JZgYlbARo8CDk0g" http://localhost:3000/
* Connected to localhost (::1) port 3000 (#0)
> GET / HTTP/1.1
> Host: localhost:3000
> User-Agent: curl/7.46.0
> Accept: */*
> Content-Type: application/json
> Authorization: Token eyJhbGciOiJBMjU2S1ciLCJ0eXAiOiJKV1MiLCJlbmMiOiJBMTI4R0NNIn0.Q672y_lD3bOU_qm5U0RDKS-YszRHfkFu.vDZaAJPz8uL5q1A4.LonJtHZMA_Ty53YBmr1zpE7-SIbTJgVgme--Tjj25dHN.goYEyM3JZgYlbARo8CDk0g
>
< HTTP/1.1 200 OK
< Date: Mon, 04 Jan 2016 13:52:59 GMT
< Content-Type: application/json; charset=utf-8
< Content-Length: 84
< Server: Jetty(9.2.10.v20150310)
<
* Connection #0 to host localhost left intact
{"status":"Logged","message":"hello logged user {:user \"admin\", :exp 1451919131}"}
```

The example code is here:
https://github.com/funcool/buddy-auth/tree/master/examples/jwe


### Signed JWT Auth Example

This example shows how to set up JWS stateless token-based authentication in a
simple Ring-based application.

Run these commands:

```
git clone https://github.com/funcool/buddy-auth.git
cd ./buddy-auth/
lein with-profile +jws-example run
```

Use *curl* with the authentication example:

```
$ curl -v -X POST -H "Content-Type: application/json" -d '{"username": "admin", "password": "secret"}' http://localhost:3000/login
> POST /login HTTP/1.1
> Host: localhost:3000
> User-Agent: curl/7.46.0
> Accept: */*
> Content-Type: application/json
> Content-Length: 43
>
* upload completely sent off: 43 out of 43 bytes
< HTTP/1.1 200 OK
< Date: Mon, 04 Jan 2016 13:49:30 GMT
< Content-Type: application/json; charset=utf-8
< Content-Length: 180
< Server: Jetty(9.2.10.v20150310)
<
* Connection #0 to host localhost left intact
{"token":"eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXUyJ9.eyJ1c2VyIjoiYWRtaW4iLCJleHAiOjE0NTE5MTg5NzB9.Kvpr1jW7JBCZYUlFjAf7xnqMZSTpSVggAgiZ6_RGZuTi1wUuP_-E8MJff23GuCwpT9bbbHNTk84uV2cdg7rKTw"}
```

Send an authenticated request with the token:

```
$ curl -v -X GET -H "Content-Type: application/json" -H "Authorization: Token eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXUyJ9.eyJ1c2VyIjoiYWRtaW4iLCJleHAiOjE0NTE5MTg5NzB9.Kvpr1jW7JBCZYUlFjAf7xnqMZSTpSVggAgiZ6_RGZuTi1wUuP_-E8MJff23GuCwpT9bbbHNTk84uV2cdg7rKTw" http://localhost:3000/
* Connected to localhost (::1) port 3000 (#0)
> GET / HTTP/1.1
> Host: localhost:3000
> User-Agent: curl/7.46.0
> Accept: */*
> Content-Type: application/json
> Authorization: Token eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXUyJ9.eyJ1c2VyIjoiYWRtaW4iLCJleHAiOjE0NTE5MTg5NzB9.Kvpr1jW7JBCZYUlFjAf7xnqMZSTpSVggAgiZ6_RGZuTi1wUuP_-E8MJff23GuCwpT9bbbHNTk84uV2cdg7rKTw
>
< HTTP/1.1 200 OK
< Date: Mon, 04 Jan 2016 13:50:15 GMT
< Content-Type: application/json; charset=utf-8
< Content-Length: 84
< Server: Jetty(9.2.10.v20150310)
<
* Connection #0 to host localhost left intact
{"status":"Logged","message":"hello logged user {:user \"admin\", :exp 1451918970}"}
```

The example code is here:
https://github.com/funcool/buddy-auth/tree/master/examples/jws


## FAQ

*What is the difference with Friend?*

_buddy-auth_ authentication and authorization facilities are lower level and less
opinionated than Friend. You can build higher-level abstractions on them. A Friend
abstraction can use _buddy-auth_.


*How can I use _buddy_ with link:http://clojure-liberator.github.io/liberator/[liberator]?*

By design, _buddy_ separates authorization from authentication. You can use one
part without including the other.

In summary: yes, you can use _buddy-auth_ with liberator.


*Can I use _buddy-auth_ with pedestal?*

You can use _buddy-auth_ with Pedestal.

https://juxt.pro/blog/posts/securing-your-clojurescript-app.html


*Can I use _buddy-auth_ with catacumba?*

Not directly.

The _buddy-auth_ API blocks because Ring and Ring-based abstractions block.
_catacumba_ is an asynchronous toolkit. It includes its own _buddy-auth_ variant
for asynchronous workflows. This variant reuses _buddy-sign_, _buddy-core_, and
_buddy-hashers_.


## Developers Guide

### Contributing

_buddy-auth_ has few contribution restrictions. Open an issue or pull request.


### Philosophy

Five important rules:

- Beautiful is better than ugly.
- Explicit is better than implicit.
- Simple is better than complex.
- Complex is better than complicated.
- Readability counts.

All contributions to _buddy-auth_ should follow these rules.


### Get the Code

_buddy-auth_ is open source. It is on
link:https://github.com/funcool/buddy-auth[GitHub].

You can clone the public repository with this command:

```
git clone https://github.com/funcool/buddy-auth
```


### Run tests

Run the tests:

```bash
lein test
```


### License

_buddy-auth_ uses the Apache License 2.0. The `LICENSE` file at the repository
root contains the full license text.
