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

(ns buddy.auth.backends.token
  "The token-based authentication and authorization backend."
  (:require [clojure.string :as str]
            [buddy.auth.protocols :as proto]
            [buddy.auth.http :as http]
            [buddy.auth :refer [authenticated?]]
            [buddy.sign.jwt :as jwt]))

(set! *warn-on-reflection* true)

(defn- handle-unauthorized-default
  "Create the default response for an unauthorized request."
  [request]
  (if (authenticated? request)
    {:status 403 :headers {} :body "Permission denied"}
    {:status 401 :headers {} :body "Unauthorized"}))

(defn- bearer-challenge
  [request]
  (if (authenticated? request)
    "Bearer error=\"insufficient_scope\", error_description=\"The request requires higher privileges than provided by the access token\""
    "Bearer error=\"invalid_token\", error_description=\"The access token is invalid\""))

(defn- handle-unauthorized
  [request bearer-challenge?]
  (let [response (handle-unauthorized-default request)]
    (if bearer-challenge?
      (assoc-in response [:headers "WWW-Authenticate"] (bearer-challenge request))
      response)))

(defn- parse-header
  [request token-name]
  (let [case-insensitive? (= "bearer" (str/lower-case token-name))
        prefix (if case-insensitive? "(?i)" "")]
    (some->> (http/-get-header request "authorization")
             (re-find (re-pattern (str prefix "^" (java.util.regex.Pattern/quote token-name) " (.+)$")))
             (second))))

(defn jws-backend
  [{:keys [secret authfn unauthorized-handler options token-name on-error bearer-challenge]
    :or {authfn identity token-name "Token"}}]
  {:pre [(ifn? authfn)]}
  (reify
    proto/IAuthentication
    (-parse [_ request]
      (parse-header request token-name))

    (-authenticate [_ request data]
      (let [claims (try
                     (jwt/unsign data secret options)
                     (catch clojure.lang.ExceptionInfo e
                       (when (fn? on-error)
                         (on-error request e))
                       nil))]
        (when claims
          (authfn claims))))

    proto/IAuthorization
    (-handle-unauthorized [_ request metadata]
      (if unauthorized-handler
        (unauthorized-handler request metadata)
        (handle-unauthorized request bearer-challenge)))))

(defn jwe-backend
  [{:keys [secret authfn unauthorized-handler options token-name on-error bearer-challenge]
    :or {authfn identity token-name "Token"}}]
  {:pre [(ifn? authfn)]}
  (reify
    proto/IAuthentication
    (-parse [_ request]
      (parse-header request token-name))
    (-authenticate [_ request data]
      (try
        (authfn (jwt/decrypt data secret options))
        (catch clojure.lang.ExceptionInfo e
          (when (fn? on-error)
            (on-error request e))
          nil)))

    proto/IAuthorization
    (-handle-unauthorized [_ request metadata]
      (if unauthorized-handler
        (unauthorized-handler request metadata)
        (handle-unauthorized request bearer-challenge)))))

(defn token-backend
  [{:keys [authfn unauthorized-handler token-name bearer-challenge]
    :or {token-name "Token"}}]
  {:pre [(ifn? authfn)]}
  (reify
    proto/IAuthentication
    (-parse [_ request]
      (parse-header request token-name))
    (-authenticate [_ request token]
      (authfn request token))

    proto/IAuthorization
    (-handle-unauthorized [_ request metadata]
      (if unauthorized-handler
        (unauthorized-handler request metadata)
        (handle-unauthorized request bearer-challenge)))))
