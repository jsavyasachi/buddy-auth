;; Copyright 2026 Savya Shanmugam
;;
;; Licensed under the Apache License, Version 2.0 (the "License");
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

(ns buddy.auth.backends.verification
  "Shared handling for failures raised while verifying credentials.")

(set! *warn-on-reflection* true)

(defn verify
  "Run `verifier`, reporting verification exceptions through `on-error`.

  The verifier is deliberately passed as a thunk so the authentication
  function is evaluated after this failure boundary and its exceptions remain
  visible to callers."
  [request on-error verifier]
  (try
    (verifier)
    (catch Exception e
      (when (fn? on-error)
        (on-error request e))
      nil)))
