# buddy-auth

Authentication and authorization for [Ring](https://github.com/ring-clojure/ring) web applications.

[![Clojars](https://img.shields.io/clojars/v/net.clojars.savya/buddy-auth.svg)](https://clojars.org/net.clojars.savya/buddy-auth)
[![cljdoc](https://cljdoc.org/badge/net.clojars.savya/buddy-auth)](https://cljdoc.org/d/net.clojars.savya/buddy-auth)
[![test](https://github.com/jsavyasachi/buddy-auth/actions/workflows/test.yml/badge.svg)](https://github.com/jsavyasachi/buddy-auth/actions/workflows/test.yml)

## Stack

<a href="https://clojure.org"><img src="https://img.shields.io/badge/Clojure-5881D8?style=flat&logo=clojure&logoColor=white" alt="Clojure" /></a>
<a href="https://github.com/ring-clojure/ring"><img src="https://img.shields.io/badge/Ring-5881D8?style=flat&logo=clojure&logoColor=white" alt="Ring" /></a>
<a href="https://github.com/funcool/buddy-sign"><img src="https://img.shields.io/badge/buddy--sign-5881D8?style=flat&logo=clojure&logoColor=white" alt="buddy-sign" /></a>

## What

`buddy-auth` provides pluggable **authentication** and **authorization** for Ring and
Ring-based web applications:

- Authentication backends: HTTP Basic, session, and token (incl. signed JWT/JWE via
  [buddy-sign](https://github.com/funcool/buddy-sign)).
- Ring middleware: `wrap-authentication` / `wrap-authorization`.
- Access rules: declarative per-route authorization with `clout` patterns.

## Installation

deps.edn:

```clojure
net.clojars.savya/buddy-auth {:mvn/version "3.1.1"}
```

Leiningen:

```clojure
[net.clojars.savya/buddy-auth "3.1.1"]
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

This is a maintenance fork of [funcool/buddy-auth](https://github.com/funcool/buddy-auth),
whose README flagged it as in maintenance mode and looking for a new maintainer. It is
modernized (current `buddy-sign`/`tools.build`, Clojure 1.11/1.12 CI) and published under
`net.clojars.savya/buddy-auth`. Original work by Andrey Antukh and contributors.

## License

Apache License 2.0. Copyright 2013-2022 Andrey Antukh. See [LICENSE](LICENSE).
