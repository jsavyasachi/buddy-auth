;; Copyright 2013-2016 Andrey Antukh <niwi@niwi.nz>
;;
;; Licensed under the Apache License, Version 2.0 (the "License")
;; you may not use this file except in compliance with the License.
;; You may obtain a copy of the License at
;;
;;     http://www.apache.org/licenses/LICENSE-2.0
;;
;; Unless required by applicable law or agreed to in writing, software
;; distributed under the License is distributed on an "AS IS" BASIS,
;; WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
;; See the License for the specific language governing permissions and
;; limitations under the License.

(ns buddy.auth.backends
  ;; buddy.auth.backends.jwks is intentionally NOT required here: it depends on
  ;; the optional jose-clj library, and requiring it statically would force that
  ;; dependency on every buddy-auth user. It is loaded lazily by `jwks` below.
  (:require [buddy.auth.backends.httpbasic :as httpbasic]
            [buddy.auth.backends.token :as token]
            [buddy.auth.backends.session :as session]))

(defn basic
  "Create an instance of the http-basic based
  authentication backend.

  This backend also implements authorization
  workflow with some defaults. This means that
  you can provide your own unauthorized-handler hook
  if the default one does not satisfy you."
  ([] (basic nil))
  ([opts] (httpbasic/http-basic-backend opts)))

(def http-basic
  "Alias for `basic`."
  basic)

(defn session
  "Create an instance of the http session based
  authentication backend.

  This backend also implements authorization
  workflow with some defaults. This means that
  you can provide your own unauthorized-handler hook
  if the default one does not satisfy you."
  ([] (session nil))
  ([opts] (session/session-backend opts)))

(defn jws
  "Create an instance of the jws (signed JWT)
  based authentication backend.

  This backend also implements authorization workflow
  with some defaults. This means that you can provide
  your own unauthorized-handler hook if the default one
  does not satisfy you."
  ([] (jws nil))
  ([opts] (token/jws-backend opts)))

(defn jwe
  "Create an instance of the jwe (encrypted JWT
  based authentication backend.

  This backend also implements authorization workflow
  with some defaults. This means that you can provide
  your own unauthorized-handler hook if the default one
  does not satisfy you."
  ([] (jwe nil))
  ([opts] (token/jwe-backend opts)))

(defn jwks
  "Create an instance of the JWKS based authentication
  backend.

  This backend validates bearer tokens against a JWK Set
  or JWKS endpoint and supports full claim validation via
  the :options map.

  Requires the optional `net.clojars.savya/jose-clj`
  dependency on the classpath; add it to your project to
  use this backend. A clear exception is thrown otherwise.

  This backend also implements authorization workflow
  with some defaults. This means that you can provide
  your own unauthorized-handler hook if the default one
  does not satisfy you."
  ([opts]
   (try
     (require 'buddy.auth.backends.jwks)
     (catch Exception e
       (throw (ex-info (str "The jwks backend requires the optional "
                            "net.clojars.savya/jose-clj dependency on the "
                            "classpath. Add it to your project to use this backend.")
                       {:missing-dependency 'net.clojars.savya/jose-clj}
                       e))))
   ((resolve 'buddy.auth.backends.jwks/jwks-backend) opts)))

(defn token
  "Create an instance of the generic token based
  authentication backend.

  This backend also implements authorization workflow
  with some defaults. This means that you can provide
  your own unauthorized-handler hook if the default one
  does not satisfy you."
  ([] (token nil))
  ([opts] (token/token-backend opts)))
