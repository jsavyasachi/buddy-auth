(ns buddy.auth.backends.jwks-tests
  (:require [clojure.test :refer :all]
            [buddy.auth :refer [authenticated? throw-unauthorized]]
            [buddy.auth.backends :as backends]
            [buddy.auth.middleware :refer [wrap-authentication wrap-authorization]]
            [buddy.core.codecs :as codecs]
            [buddy.core.codecs.base64 :as b64]
            [clojure.string :as str]
            [clojure.test.check :as tc]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]
            [jose.jwk :as jose-jwk]
            [jose.jwks :as jose-jwks]
            [jose.jwt :as jose-jwt]))

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
(def symmetric-signing-key (jose-jwk/generate :oct {:kid "jwks-symmetric-key"
                                                   :use :sig
                                                   :alg :hs256}))
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

(defn sign-symmetric-token
  [claims]
  (jose-jwt/sign symmetric-signing-key claims {:alg :hs256}))

(defn replace-jwt-algorithm
  [token algorithm]
  (let [header (-> (b64/encode (str "{\"alg\":\"" (name algorithm) "\",\"typ\":\"JWT\"}"))
                   codecs/bytes->str
                   (str/replace "+" "-")
                   (str/replace "/" "_")
                   (str/replace "=" ""))]
    (str header "." (second (str/split token #"\.")) "." (nth (str/split token #"\.") 2))))

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

(def unexpected-jws-algorithm-gen
  (gen/elements [:none :hs256 :es256]))

(deftest jwks-rejects-unexpected-signing-algorithms
  (let [result (tc/quick-check
                30
                (prop/for-all [algorithm unexpected-jws-algorithm-gen]
                  (let [token (sign-symmetric-token claims)
                        token (replace-jwt-algorithm token algorithm)
                        request (make-jwks-request token)
                        handler (wrap-authentication identity jwks-backend)
                        request' (handler request)]
                    (and (not (authenticated? request'))
                         (nil? (:identity request'))))))]
    (is (= true (:pass? result)) (pr-str result))))
