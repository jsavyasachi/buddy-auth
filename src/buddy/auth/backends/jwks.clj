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

(ns buddy.auth.backends.jwks
  "The JWKS based authentication and authorization backend."
  (:require [buddy.auth.protocols :as proto]
            [buddy.auth.http :as http]
            [buddy.auth :refer [authenticated?]]
            [jose.jwt :as jose-jwt]
            [jose.jwks :as jose-jwks]))

(set! *warn-on-reflection* true)

(defn- handle-unauthorized-default
  "A default response constructor for an unauthorized request."
  [request]
  (if (authenticated? request)
    {:status 403 :headers {} :body "Permission denied"}
    {:status 401 :headers {} :body "Unauthorized"}))

(defn- parse-header
  [request token-name]
  (some->> (http/-get-header request "authorization")
           (re-find (re-pattern (str "^" token-name " (.+)$")))
           (second)))

(defn- jwks-source
  [{:keys [source jwks-url jwks-opts]}]
  (cond
    (and source jwks-url)
    (throw (IllegalArgumentException. "Expected exactly one of :source or :jwks-url"))

    source
    source

    jwks-url
    (jose-jwks/remote-source jwks-url (or jwks-opts {}))

    :else
    (throw (IllegalArgumentException. "Expected exactly one of :source or :jwks-url"))))

(defn jwks-backend
  [{:keys [authfn unauthorized-handler options token-name on-error]
    :as opts
    :or {authfn identity options {} token-name "Bearer"}}]
  {:pre [(ifn? authfn)]}
  (let [source (jwks-source opts)]
    (reify
      proto/IAuthentication
      (-parse [_ request]
        (parse-header request token-name))

      (-authenticate [_ request data]
        (try
          (authfn (jose-jwt/verify-with-jwks source data options))
          (catch clojure.lang.ExceptionInfo e
            (when (fn? on-error)
              (on-error request e))
            nil)))

      proto/IAuthorization
      (-handle-unauthorized [_ request metadata]
        (if unauthorized-handler
          (unauthorized-handler request metadata)
          (handle-unauthorized-default request))))))
