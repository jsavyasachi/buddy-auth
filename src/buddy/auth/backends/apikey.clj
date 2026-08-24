(ns buddy.auth.backends.apikey
  "API-key authentication and authorization backend."
  (:require [buddy.auth.protocols :as proto]
            [buddy.auth.http :as http]
            [buddy.auth :refer [authenticated?]]))

(set! *warn-on-reflection* true)

(defn- non-empty-string?
  [value]
  (and (string? value) (not-empty value)))

(defn parse-key
  "Extract an API key from a Ring request according to its location."
  [request location header-name cookie-name query-param]
  (let [key (case location
              :header (http/-get-header request header-name)
              :cookie (get-in request [:cookies cookie-name :value])
              :query (get-in request [:query-params query-param]))]
    (when (non-empty-string? key)
      key)))

(defn- handle-unauthorized-default
  [request]
  (if (authenticated? request)
    (http/response "Permission denied" 403)
    (http/response "Unauthorized" 401)))

(defn api-key-backend
  [& [{:keys [authfn unauthorized-handler location header-name cookie-name query-param]
       :or {location :header
            header-name "X-API-Key"
            cookie-name "api-key"
            query-param "api-key"}}]]
  (when-not (ifn? authfn)
    (throw (IllegalArgumentException. ":authfn must be callable")))
  (when-not (#{:header :cookie :query} location)
    (throw (IllegalArgumentException.
            ":location must be :header, :cookie, or :query")))
  (doseq [[option value] [[:header-name header-name]
                          [:cookie-name cookie-name]
                          [:query-param query-param]]]
    (when-not (non-empty-string? value)
      (throw (IllegalArgumentException.
              (str option " must be a non-empty string")))))
  (reify
    proto/IAuthentication
    (-parse [_ request]
      (parse-key request location header-name cookie-name query-param))
    (-authenticate [_ _ key]
      (authfn key))
    proto/IAuthorization
    (-handle-unauthorized [_ request metadata]
      (if unauthorized-handler
        (unauthorized-handler request metadata)
        (handle-unauthorized-default request)))))
