;; Copyright 2013-2017 Andrey Antukh <niwi@niwi.nz>
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

(ns buddy.auth.middleware
  (:require [buddy.auth.protocols :as proto]))

(set! *warn-on-reflection* true)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Authentication
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn authenticate-request
  "Run the authentication backend chain for a request. Return the identity of
  the first backend that authenticates the request.

  This public function is for internal use. It helps in environments other than Ring."
  [request backends]
  (loop [[backend & backends] backends]
    (when backend
      (let [request (assoc request :auth-backend backend)]
        (or (some->> request
                     (proto/-parse backend)
                     (proto/-authenticate backend request))
            (recur backends))))))

(defn authentication-request
  "Update a request with authentication. If multiple `backends` are given,
  each backend can authenticate the request.

  This public function is for internal use. It helps in environments other than Ring."
  [request & backends]
  (if-let [authdata (authenticate-request request backends)]
    (assoc request :identity authdata)
    request))

(defn wrap-authentication
  "Ring middleware that enables authentication for a Ring handler. If multiple
  `backends` are given, each backend can authenticate the request."
  [handler & backends]
  (fn
    ([request]
     (handler (apply authentication-request request backends)))
    ([request respond raise]
     (handler (apply authentication-request request backends) respond raise))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Authorization
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn- fn->authorization-backend
  "Given a function with two parameters, return an anonymous object that
  implements the IAuthorization protocol."
  [callable]
  {:pre [(fn? callable)]}
  (reify
    proto/IAuthorization
    (-handle-unauthorized [_ request errordata]
      (callable request errordata))))

(defn authorization-error
  "Handle authorization errors.

  The `backend` parameter must be a function that accepts a request and errordata
  hash map, or an instance that satisfies the IAuthorization protocol."
  [request e backend]
  (let [backend (cond
                  (fn? backend)
                  (fn->authorization-backend backend)

                  (satisfies? proto/IAuthorization backend)
                  backend)]
    (if (instance? clojure.lang.ExceptionInfo e)
      (let [data (ex-data e)]
        (if (= (:buddy.auth/type data) :buddy.auth/unauthorized)
          (->> (:buddy.auth/payload data)
               (proto/-handle-unauthorized backend request))
          (throw e)))
      (if (satisfies? proto/IAuthorizationdError e)
        (->> (proto/-get-error-data e)
             (proto/-handle-unauthorized backend request))
        (throw e)))))

(defn wrap-authorization
  "Ring middleware that enables an authorization workflow for a Ring handler.

  The `backend` parameter must be a function that accepts a request and errordata
  hash map, or an instance that satisfies the IAuthorization protocol."
  [handler backend]
  (fn
    ([request]
     (try (handler request)
          (catch Exception e
            (authorization-error request e backend))))
    ([request respond raise]
     (letfn [(wrapped-respond [response]
               (try
                 (respond response)
                 (catch Exception e
                   (raise e))))
             (wrapped-raise [e]
               (try
                 (wrapped-respond (authorization-error request e backend))
                 (catch Exception e
                   (raise e))))]
       (try
         (handler request wrapped-respond wrapped-raise)
         (catch Exception e
           (wrapped-raise e)))))))
