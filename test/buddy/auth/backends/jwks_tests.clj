(ns buddy.auth.backends.jwks-tests
  (:require [clojure.test :refer :all]
            [buddy.auth :refer [authenticated? throw-unauthorized]]
            [buddy.auth.backends :as backends]
            [buddy.auth.middleware :refer [wrap-authentication wrap-authorization]]
            [buddy.auth.backends.jwks :as jwks]
            [jose.jwk :as jose-jwk]
            [jose.jwks :as jose-jwks]
            [jose.jwt :as jose-jwt])
  )

(set! *warn-on-reflection* true)

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
  (testing "Authenticate a valid bearer token with the JWKS backend"
    (let [request (make-jwks-request (sign-token claims))
          handler (wrap-authentication identity jwks-backend)
          request' (handler request)]
      (is (authenticated? request'))
      (is (= (:identity request') claims))))

  (testing "Return 401 for an invalid bearer token"
    (let [request (make-jwks-request "garbage")
          handler (-> (fn [_] (throw-unauthorized))
                      (wrap-authorization jwks-backend)
                      (wrap-authentication jwks-backend))
          response (handler request)]
      (is (= (:status response) 401))
      (is (= (:body response) "Unauthorized"))))

  (testing "Reject a token signed by a key outside the source"
    (let [request (make-jwks-request (sign-token other-signing-key claims))
          handler (wrap-authentication identity jwks-backend)
          request' (handler request)]
      (is (not (authenticated? request')))
      (is (nil? (:identity request')))))

  (testing "Reject claim mismatches from validation options"
    (let [backend (backends/jwks {:source jwks-source
                                  :options {:iss "https://other-issuer.example"
                                            :algs #{:rs256}}})
          request (make-jwks-request (sign-token claims))
          handler (wrap-authentication identity backend)
          request' (handler request)]
      (is (not (authenticated? request')))
      (is (nil? (:identity request')))))

  (testing "Call on-error when verification fails"
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

  (testing "Transform authenticated claims with authfn"
    (let [request (make-jwks-request (sign-token claims))
          handler (wrap-authentication identity jwks-backend-with-authfn)
          request' (handler request)]
      (is (authenticated? request'))
      (is (= {:subject "user-1"
              :issuer "https://issuer.example"}
             (:identity request')))))

  (testing "Return 403 for an authenticated unauthorized request"
    (let [request (make-jwks-request (sign-token claims))
          handler (-> (fn [_] (throw-unauthorized))
                      (wrap-authorization jwks-backend)
                      (wrap-authentication jwks-backend))
          response (handler request)]
      (is (= (:status response) 403))
      (is (= (:body response) "Permission denied")))))

(deftest jwks-backend-construction-test
  (testing "Require an expected JWT algorithm"
    (is (thrown-with-msg? IllegalArgumentException
                          #"Expected JWT algorithm is required"
                          (backends/jwks {:source jwks-source}))))

  (testing "Require exactly one JWK source"
    (is (thrown? IllegalArgumentException (backends/jwks {})))
    (is (thrown? IllegalArgumentException
                 (backends/jwks {:source jwks-source
                                 :jwks-url "https://issuer.example/jwks"}))))

  (testing "Report an invalid JWKS URL when the backend is created"
    (try
      (backends/jwks {:jwks-url "not a url"})
      (is false "Expected invalid JWKS URL")
      (catch clojure.lang.ExceptionInfo e
        (is (= :invalid-url (:jose/error (ex-data e))))))))

(deftest oidc-provider-test
  (let [issuer "https://issuer.example"
        discover (some-> (ns-resolve 'buddy.auth.backends 'discover-jwks-url) deref)]
    (if discover
      (is (= "https://issuer.example/keys"
             (discover issuer (fn [_] {"jwks_uri" "https://issuer.example/keys"}))))
      (is false "OIDC discovery helper is missing"))
    (if-let [oidc (some-> (ns-resolve 'buddy.auth.backends 'oidc) deref)]
      (let [valid-claims (assoc claims :aud ["api://buddy-auth" "other"]
                                :azp "api://buddy-auth"
                                :nonce "nonce-1")
            backend (oidc {:issuer issuer
                           :source jwks-source
                           :options {:algs #{:rs256}}
                           :audience "api://buddy-auth"
            :nonce "nonce-1"
                           :discovery-fn (fn [_] "https://issuer.example/keys")})
            request (make-jwks-request (sign-token valid-claims))
            wrong-azp (make-jwks-request (sign-token (assoc valid-claims :azp "other")))
            wrong-nonce (make-jwks-request (sign-token (assoc valid-claims :nonce "other")))]
        (is (authenticated? ((wrap-authentication identity backend) request)))
        (is (not (authenticated? ((wrap-authentication identity backend) wrong-azp))))
        (is (not (authenticated? ((wrap-authentication identity backend) wrong-nonce)))))
      (is false "OIDC backend helper is missing"))))

(deftest oidc-construction-discovers-jwks-test
  (let [calls (atom [])]
    (is (some? (backends/oidc {:issuer "https://issuer.example"
                               :options {:algs #{:rs256}}
                               :discovery-fn (fn [issuer]
                                               (swap! calls conj issuer)
                                               "https://issuer.example/keys")})))
    (is (= ["https://issuer.example"] @calls))))

(deftest oidc-errors-are-not-mislabeled-test
  (with-redefs [jwks/discover-jwks-url
                (fn [_]
                  (throw (ex-info "discovery failed" {:error :discovery-failed})))]
    (try
      (backends/discover-jwks-url "https://issuer.example")
      (is false "Expected discovery failure")
      (catch clojure.lang.ExceptionInfo e
        (is (= :discovery-failed (:error (ex-data e))))
        (is (nil? (:missing-dependency (ex-data e))))))))
