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

(ns buddy.auth.backends.httpbasic
  "The HTTP Basic authentication and authorization backend."
  (:require [buddy.auth.protocols :as proto]
            [buddy.auth.http :as http]
            [buddy.auth :refer [authenticated?]]
            [buddy.core.codecs :as codecs]
            [buddy.core.codecs.base64 :as b64]
            [clojure.string :as str]))

(defn- parse-header
  "Extract and parse the HTTP Basic header from a request.

  RFC 7617, section 2, defines the decoded payload as `user-id \":\" password`.
  A payload with no colon is malformed - as is anything that was not valid
  base64 to begin with, which decodes to bytes that carry no colon either - so
  no credentials are returned for it. An empty password (`\"user:\"`) is legal
  and does parse."
  [request]
  (let [pattern (re-pattern "^Basic (.+)$")
        decoded (some->> (http/-get-header request "authorization")
                         (re-find pattern)
                         (second)
                         (b64/decode)
                         (codecs/bytes->str))]
    (when (some-> decoded (str/includes? ":"))
      (let [[username password] (str/split decoded #":" 2)]
        {:username username
         :password password}))))

(defn http-basic-backend
  [& [{:keys [realm authfn unauthorized-handler] :or {realm "Buddy Auth"}}]]
  {:pre [(ifn? authfn)]}
  (reify
    proto/IAuthentication
    (-parse [_ request]
      (parse-header request))
    (-authenticate [_ request data]
      (authfn request data))

    proto/IAuthorization
    (-handle-unauthorized [_ request metadata]
      (if unauthorized-handler
        (unauthorized-handler request (assoc metadata :realm realm))
        (if (authenticated? request)
          (http/response "Permission denied" 403)
          (http/response "Unauthorized" 401
                         {"WWW-Authenticate" (format "Basic realm=\"%s\"" realm)}))))))
