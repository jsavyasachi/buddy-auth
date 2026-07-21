(ns buddy.auth.backends.jwks-tests
  (:require [clojure.test :refer :all]
            [buddy.auth :refer [authenticated? throw-unauthorized]]
            [buddy.auth.backends :as backends]
            [buddy.auth.middleware :refer [wrap-authentication wrap-authorization]]
            [jose.jwk :as jose-jwk]
            [jose.jwks :as jose-jwks]
            [jose.jwt :as jose-jwt]))

(def claims {:iss "https://issuer.example"
             :aud ["api://buddy-auth"]
             :sub "user-1"
             "scope" "read:things"})

(def signing-key (jose-jwk/generate :rsa {:kid "jwks-test-key"
                                          :use :sig
                                          :alg :rs256}))
(def other-signing-key (jose-jwk/generate :rsa {:kid "jwks-other-key"
                                                :use :sig
                                                :alg :rs256}))
(def jwks-source (jose-jwks/local-source [(jose-jwk/public-jwk signing-key)]))

(def jwks-backend
  (backends/jwks {:source jwks-source
                  :options {:iss "https://issuer.example"
                            :aud "api://buddy-auth"
                            :required [:sub]
                            :algs #{:rs256}}}))

(def jwks-backend-with-authfn
  (backends/jwks {:source jwks-source
                  :options {:algs #{:rs256}}
                  :authfn (fn [claims]
                            {:subject (:sub claims)
                             :issuer (:iss claims)})}))

(defn sign-token
  ([claims]
   (sign-token signing-key claims))
  ([key claims]
   (jose-jwt/sign key claims {:alg :rs256})))

(defn make-jwks-request
  [token]
  {:headers {"authorization" (str "Bearer " token)}})

(deftest jwks-backend-test
  (testing "Jwks backend authenticates a valid bearer token"
    (let [request (make-jwks-request (sign-token claims))
          handler (wrap-authentication identity jwks-backend)
          request' (handler request)]
      (is (authenticated? request'))
      (is (= (:identity request') claims))))

  (testing "Jwks backend rejects a garbage bearer token with 401"
    (let [request (make-jwks-request "garbage")
          handler (-> (fn [_] (throw-unauthorized))
                      (wrap-authorization jwks-backend)
                      (wrap-authentication jwks-backend))
          response (handler request)]
      (is (= (:status response) 401))
      (is (= (:body response) "Unauthorized"))))

  (testing "Jwks backend rejects a token signed by a key outside the source"
    (let [request (make-jwks-request (sign-token other-signing-key claims))
          handler (wrap-authentication identity jwks-backend)
          request' (handler request)]
      (is (not (authenticated? request')))
      (is (nil? (:identity request')))))

  (testing "Jwks backend rejects claim mismatches from validation options"
    (let [backend (backends/jwks {:source jwks-source
                                  :options {:iss "https://other-issuer.example"
                                            :algs #{:rs256}}})
          request (make-jwks-request (sign-token claims))
          handler (wrap-authentication identity backend)
          request' (handler request)]
      (is (not (authenticated? request')))
      (is (nil? (:identity request')))))

  (testing "Jwks backend invokes on-error on verification failure"
    (let [p (promise)
          backend (backends/jwks {:source jwks-source
                                  :options {:algs #{:rs256}}
                                  :on-error (fn [_ e] (deliver p (ex-data e)))})
          request (make-jwks-request "garbage")
          handler (-> identity
                      (wrap-authorization backend)
                      (wrap-authentication backend))
          response (handler request)]
      (is (= response request))
      (is (= :parse-failure (:jose/error (deref p 1000 false))))))

  (testing "Jwks backend transforms authenticated claims with authfn"
    (let [request (make-jwks-request (sign-token claims))
          handler (wrap-authentication identity jwks-backend-with-authfn)
          request' (handler request)]
      (is (authenticated? request'))
      (is (= {:subject "user-1"
              :issuer "https://issuer.example"}
             (:identity request')))))

  (testing "Jwks backend authorization yields 403 for authenticated unauthorized requests"
    (let [request (make-jwks-request (sign-token claims))
          handler (-> (fn [_] (throw-unauthorized))
                      (wrap-authorization jwks-backend)
                      (wrap-authentication jwks-backend))
          response (handler request)]
      (is (= (:status response) 403))
      (is (= (:body response) "Permission denied")))))

(deftest jwks-backend-construction-test
  (testing "Jwks backend requires an expected JWT algorithm"
    (is (thrown-with-msg? IllegalArgumentException
                          #"Expected JWT algorithm is required"
                          (backends/jwks {:source jwks-source}))))

  (testing "Jwks backend requires exactly one JWK source"
    (is (thrown? IllegalArgumentException (backends/jwks {})))
    (is (thrown? IllegalArgumentException
                 (backends/jwks {:source jwks-source
                                 :jwks-url "https://issuer.example/jwks"}))))

  (testing "Jwks backend surfaces invalid JWKS URL errors at construction"
    (try
      (backends/jwks {:jwks-url "not a url"})
      (is false "Expected invalid JWKS URL")
      (catch clojure.lang.ExceptionInfo e
        (is (= :invalid-url (:jose/error (ex-data e))))))))
