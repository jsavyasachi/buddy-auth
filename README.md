# buddy-auth

Authentication and authorization for [Ring](https://github.com/ring-clojure/ring) web applications.

[![Clojars Project](https://img.shields.io/clojars/v/net.clojars.savya/buddy-auth.svg)](https://clojars.org/net.clojars.savya/buddy-auth)
[![cljdoc](https://cljdoc.org/badge/net.clojars.savya/buddy-auth)](https://cljdoc.org/d/net.clojars.savya/buddy-auth)
[![test](https://github.com/jsavyasachi/buddy-auth/actions/workflows/test.yml/badge.svg)](https://github.com/jsavyasachi/buddy-auth/actions/workflows/test.yml)

## Stack

<a href="https://clojure.org"><img src="https://img.shields.io/badge/Clojure-5881D8?style=flat&logo=clojure&logoColor=white" alt="Clojure" /></a>
<a href="https://github.com/ring-clojure/ring"><img src="https://img.shields.io/badge/Ring-5881D8?style=flat&logo=clojure&logoColor=white" alt="Ring" /></a>
<a href="https://github.com/funcool/buddy-sign"><img src="https://img.shields.io/badge/buddy--sign-5881D8?style=flat&logo=clojure&logoColor=white" alt="buddy-sign" /></a>

## What

`buddy-auth` provides pluggable **authentication** and **authorization** for Ring and
Ring-based web applications:

- Authentication backends: API key, HTTP Basic, session, and token. Token covers signed
  JWT and JWE through [buddy-sign](https://github.com/funcool/buddy-sign), and
  JWKS/OIDC token validation through
  [jose-clj](https://github.com/jsavyasachi/jose-clj).
- Ring middleware: `wrap-authentication` / `wrap-authorization`.
- Access rules: declarative authorization for each route with `clout` patterns.

## Installation

deps.edn:

```clojure
net.clojars.savya/buddy-auth {:mvn/version "4.0.2"}
```

Leiningen:

```clojure
[net.clojars.savya/buddy-auth "4.0.2"]
```

## Usage

```clojure
(require '[buddy.auth :refer [authenticated?]]
         '[buddy.auth.backends :as backends]
         '[buddy.auth.middleware :refer [wrap-authentication]])

(def backend (backends/basic {:authfn my-authfn}))

(def app
  (-> handler
      (wrap-authentication backend)))
```

Full guide: [cljdoc](https://cljdoc.org/d/net.clojars.savya/buddy-auth) and `doc/user-guide.md`.

## Maintenance fork

This is a maintenance fork of [funcool/buddy-auth](https://github.com/funcool/buddy-auth).
The README of that project said it was in maintenance mode and needed a new maintainer.
This fork uses current `buddy-sign` and `tools.build`. It runs CI on Clojure 1.11 and
1.12. It is published as `net.clojars.savya/buddy-auth`. Andrey Antukh and contributors
did the original work.

## License

Copyright © 2013-2022 Andrey Antukh.

Maintenance fork (2026) by Savyasachi, original: https://github.com/funcool/buddy-auth.
Distributed under the [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0), preserving the original license.
