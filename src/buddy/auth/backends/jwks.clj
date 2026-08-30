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
  "The JWKS authentication and authorization backend."
  (:require [clojure.string :as str]
            [buddy.auth.protocols :as proto]
            [buddy.auth.http :as http]
            [buddy.auth :refer [authenticated?]]
            [buddy.auth.backends.verification :as verification]
            [jose.jwt :as jose-jwt]
            [jose.jwks :as jose-jwks])
  (:import (com.nimbusds.jose.util JSONObjectUtils)
           (java.net URI)
           (java.net.http HttpClient HttpRequest HttpResponse HttpResponse$BodyHandlers)
           (java.time Duration)))

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

(defn- http-get-json
  [url]
  (let [request (-> (HttpRequest/newBuilder (URI. url))
                    (.timeout (Duration/ofSeconds 10))
                    (.header "Accept" "application/json")
                    (.GET)
                    (.build))
        ^HttpResponse response (.send (HttpClient/newHttpClient)
                                       request
                                       (HttpResponse$BodyHandlers/ofString))]
    (when-not (= 200 (.statusCode response))
      (throw (ex-info "OIDC discovery request failed"
                      {:url url :status (.statusCode response)})))
    (JSONObjectUtils/parse ^String (.body response))))

(defn discover-jwks-url
  "Fetch the OIDC discovery document and return its `jwks_uri`.

  The two-argument form accepts a fetch function for callers that provide
  their own HTTP transport or for isolated testing."
  ([issuer]
   (discover-jwks-url issuer http-get-json))
  ([issuer fetch-json]
   (let [issuer (str issuer)
         discovery-url (str (if (.endsWith ^String issuer "/")
                              (subs issuer 0 (dec (count issuer)))
                              issuer)
                            "/.well-known/openid-configuration")
         document (fetch-json discovery-url)
         jwks-url (get document "jwks_uri")]
     (if (string? jwks-url)
       jwks-url
       (throw (ex-info "OIDC discovery document has no jwks_uri"
                       {:url discovery-url}))))))

(defn- claim-value
  [claims key]
  (or (get claims key) (get claims (name key))))

(defn- oidc-verifier
  [audience nonce verifier]
  (fn [claims context]
    (and (or (nil? verifier) (verifier claims context))
         (or (nil? nonce)
             (= nonce (claim-value claims :nonce)))
         (or (= :any audience)
             (let [aud (claim-value claims :aud)
                   aud (if (sequential? aud) aud [aud])]
               (and (contains? (set aud) audience)
                    (or (<= (count aud) 1)
                        (= audience (claim-value claims :azp)))))))))

(declare jwks-backend)

(defn oidc-backend
  "Create a JWKS backend from an OIDC issuer.

  Discovery is performed when no `:source` or `:jwks-url` is supplied. The
  expected audience is required and is configured with `:audience` (or
  `:options {:aud ...}`), and an expected nonce with `:nonce`.

  Audience validation stops a token the issuer minted for a different relying
  party from authenticating here (OIDC Core 3.1.3.7). Pass the explicit
  `:audience :any` sentinel to opt out of it."
  [{:keys [issuer audience nonce discovery-fn options]
    :as opts
    :or {options {}}}]
  (when-not issuer
    (throw (IllegalArgumentException. "Expected OIDC :issuer")))
  (let [audience (or audience (:aud options))]
    (when-not audience
      (throw (IllegalArgumentException.
              (str "Expected OIDC :audience (or :options {:aud ...}); "
                   "pass :audience :any to opt out of audience validation"))))
    (let [nonce (if (contains? opts :nonce) nonce (:nonce options))
          verifier (oidc-verifier audience nonce (:verifier options))
          options (cond-> (assoc (dissoc options :nonce :verifier) :iss issuer)
                    (= :any audience) (dissoc :aud)
                    (and (not= :any audience)
                         (not (contains? options :aud))) (assoc :aud audience))
          jwks-url (or (:jwks-url opts)
                       (when-not (:source opts)
                         ((or discovery-fn discover-jwks-url) issuer)))]
      (jwks-backend (assoc opts
                           :jwks-url jwks-url
                           :options (assoc options :verifier verifier))))))

(defn jwks-backend
  "Create a JWKS authentication backend.

  :options must contain :algs or :alg to declare the expected JWT algorithm.
  For example, pass :options {:algs #{:rs256}}."
  [{:keys [authfn unauthorized-handler options token-name on-error bearer-challenge]
    :as opts
    :or {authfn identity options {} token-name "Bearer"}}]
  {:pre [(ifn? authfn)]}
  (let [source (jwks-source opts)]
    (when-not (or (contains? options :alg) (contains? options :algs))
      (throw (IllegalArgumentException.
              "Expected JWT algorithm is required (RFC 8725); pass :options {:algs #{:rs256}}")))
    (reify
      proto/IAuthentication
      (-parse [_ request]
        (parse-header request token-name))

      (-authenticate [_ request data]
        (let [claims (verification/verify
                      request on-error
                      #(jose-jwt/verify-with-jwks source data options))]
          (when claims
            (authfn claims))))

      proto/IAuthorization
      (-handle-unauthorized [_ request metadata]
        (if unauthorized-handler
          (unauthorized-handler request metadata)
          (handle-unauthorized request bearer-challenge))))))
