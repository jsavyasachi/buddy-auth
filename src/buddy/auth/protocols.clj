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

(ns buddy.auth.protocols
  "Main authentication and authorization abstractions defined as protocols.")

(defprotocol IAuthentication
  "Protocol that defines workflow steps for all authentication backends."
  (-parse [_ request]
    "Parse a token from the request. If it returns `nil`, the `authenticate`
    phase is skipped and the handler is called directly.")
  (-authenticate [_ request data]
    "Given a request and parsed data from the previous step, authenticate the data.

    If this method returns a non-nil value, the request is authenticated. The
    value is attached to the request under the `:identity` attribute."))

(defprotocol IAuthorization
  "Protocol that defines workflow steps for authorization exceptions."
  (-handle-unauthorized [_ request metadata]
    "This function runs when an authorization wrapper intercepts a
    `NotAuthorizedException`.

    It should return a valid ring response."))

(defprotocol IAuthorizationdError
  "Abstraction that lets a user extend the exception-based authorization system
  with user-defined types."
  (-get-error-data [_] "Get error information."))
