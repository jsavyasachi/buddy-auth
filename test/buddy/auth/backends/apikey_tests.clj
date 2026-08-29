(ns buddy.auth.backends.apikey-tests
  (:require [clojure.test :refer [deftest is]]
            [buddy.auth :refer [throw-unauthorized]]
            [buddy.auth.backends :as backends]
            [buddy.auth.backends.apikey :as apikey]
            [buddy.auth.middleware :refer [wrap-authentication wrap-authorization]]))

(defn authfn
  [key]
  (when (= key "good-key")
    {:user "alice" :scopes #{"read"}}))

(defn authenticate
  [backend request]
  ((wrap-authentication identity backend) request))

(deftest api-key-header-test
  (let [backend (backends/apikey {:authfn authfn})]
    (is (= {:user "alice" :scopes #{"read"}}
           (:identity (authenticate backend {:headers {"X-API-Key" "good-key"}}))))
    (is (nil? (:identity (authenticate backend {:headers {}}))))
    (is (nil? (:identity (authenticate backend {:headers {"X-API-Key" "bad-key"}}))))))

(deftest api-key-configurable-header-test
  (let [backend (backends/apikey {:authfn authfn
                                  :header-name "X-Custom-Key"})]
    (is (= {:user "alice" :scopes #{"read"}}
           (:identity (authenticate backend {:headers {"x-custom-key" "good-key"}}))))
    (is (nil? (:identity (authenticate backend {:headers {"X-API-Key" "good-key"}}))))))

(deftest api-key-cookie-test
  (let [backend (backends/apikey {:authfn authfn
                                  :location :cookie})]
    (is (= {:user "alice" :scopes #{"read"}}
           (:identity (authenticate backend {:cookies {"api-key" {:value "good-key"}}}))))
    (is (nil? (:identity (authenticate backend {:cookies {"api-key" {:value ""}}}))))))

(deftest api-key-query-test
  (let [backend (backends/apikey {:authfn authfn
                                  :location :query
                                  :query-param "key"})]
    (is (= {:user "alice" :scopes #{"read"}}
           (:identity (authenticate backend {:query-params {"key" "good-key"}}))))
    (is (nil? (:identity (authenticate backend {:query-params {"other" "good-key"}}))))))

(deftest api-key-authorization-test
  (let [backend (backends/apikey {:authfn authfn})
        handler (-> (fn [request]
                      (if (:identity request)
                        request
                        (throw-unauthorized {:message "missing key"})))
                    (wrap-authorization backend)
                    (wrap-authentication backend))]
    (is (= 401 (:status (handler {:headers {}}))))
    (is (= {:user "alice" :scopes #{"read"}}
           (:identity (handler {:headers {"X-API-Key" "good-key"}}))))
    (is (= 403 (:status ((wrap-authorization
                          (fn [_] (throw-unauthorized {})) backend)
                         {:identity {:user "alice"}}))))))

(deftest api-key-custom-unauthorized-handler-test
  (let [backend (backends/apikey {:authfn authfn
                                  :unauthorized-handler
                                  (fn [_ metadata] {:status 499 :body metadata})})
        response ((wrap-authorization
                   (fn [_] (throw-unauthorized {:message "nope"})) backend)
                  {:headers {}})]
    (is (= 499 (:status response)))
    (is (= "nope" (get-in response [:body :message])))))

(deftest api-key-configuration-test
  (is (some? (backends/api-key {:authfn authfn})))
  (is (thrown? IllegalArgumentException
               (backends/apikey {:authfn authfn :location :body})))
  (is (thrown? IllegalArgumentException
               (backends/apikey {:location :header})))
  (is (thrown? IllegalArgumentException
               (backends/apikey {:authfn authfn :header-name ""}))))

(deftest api-key-parse-is-safe-for-malformed-requests-test
  (let [parse #'apikey/parse-key]
    (is (nil? (parse {:headers {"X-API-Key" []}} :header "X-API-Key" "api-key" "api-key")))
    (is (nil? (parse {:cookies {"api-key" "not-a-cookie-map"}} :cookie "X-API-Key" "api-key" "api-key")))
    (is (nil? (parse {:query-params {"key" [:bad]}} :query "X-API-Key" "api-key" "key")))))
