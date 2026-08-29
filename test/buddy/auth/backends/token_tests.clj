(ns buddy.auth.backends.token-tests
  (:require [clojure.test :refer [deftest is testing]]
            [buddy.core.hash :as hash]
            [buddy.core.keys :as keys]
            [buddy.sign.jwt :as jwt]
            [buddy.auth :refer [throw-unauthorized authenticated?]]
            [buddy.auth.backends :as backends]
            [buddy.auth.backends.token :as token]
            [buddy.auth.middleware :refer [wrap-authentication wrap-authorization]]))

(set! *warn-on-reflection* true)

(def secret "test-secret-key")

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Helpers
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn make-request
  [token]
  (let [header (format "Token %s" token)]
    {:headers {"auThorIzation" header}}))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Tests: parse
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(deftest token-parse-test
  (testing "Parse an authorization header"
    (let [request (make-request "foo")
          parse #'token/parse-header
          parsed  (parse request "Token")]
      (is (= parsed "foo"))))

  (testing "Return nil for a different authorization header name"
    (let [parse #'token/parse-header
          parsed (parse (make-request "foo") "MyToken")]
      (is (= parsed nil)))))

(deftest bearer-parse-is-case-insensitive-test
  (testing "Parse a Bearer authorization scheme without regard to case"
    (let [parse #'token/parse-header]
      (is (= "foo" (parse {:headers {"authorization" "bEaReR foo"}} "Bearer"))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Tests: JWS
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(def jws-secret "mysuperjwssecret")
(def jws-backend (backends/jws {:secret jws-secret}))
(def jws-backend-with-authfn (backends/jws {:secret jws-secret
                                            :authfn (constantly ::jws-authorized)}))
(def jws-data {:userid 1})

(def rsa-privkey (keys/private-key "test/_files/privkey.3des.rsa.pem" "secret"))
(def rsa-pubkey (keys/public-key "test/_files/pubkey.3des.rsa.pem"))
(def jws-backend-rsa (backends/jws {:secret rsa-pubkey :options {:alg :ps512}}))

(defn make-jws-request
  ([data secret]
   (make-jws-request data secret {}))
  ([data secret options]
   (let [header (->> (jwt/sign data secret options)
                     (format "Token %s"))]
     {:headers {"authorization" header}})))

(deftest jws-tests
  (testing "Authenticate with the JWS token backend"
    (let [request (make-jws-request jws-data jws-secret)
          handler (wrap-authentication identity jws-backend)
          request' (handler request)]
      (is (authenticated? request'))
      (is (= (:identity request') jws-data))))

  (testing "Authenticate the JWS token backend with an RSA key"
    (let [request (make-jws-request jws-data rsa-privkey {:alg :ps512})
          handler (wrap-authentication identity jws-backend-rsa)
          request' (handler request)]
      (is (authenticated? request'))
      (is (= (:identity request') jws-data))))

  (testing "Return nil for JWS authentication with a wrong key"
    (let [request (make-jws-request jws-data  "wrong-key")
          handler (wrap-authentication identity jws-backend)
          request' (handler request)]
      (is (not (authenticated? request')))
      (is (nil? (:identity request')))))

  (testing "Propagate errors from a custom JWS authfn"
    (let [request (make-jws-request jws-data jws-secret)
          backend (backends/jws {:secret jws-secret
                                 :authfn (fn [_]
                                           (throw (ex-info "authfn failed" {})))})
          handler (wrap-authentication identity backend)]
      (is (thrown-with-msg? clojure.lang.ExceptionInfo
                            #"authfn failed"
                            (handler request)))))

  (testing "Return nil for JWS authentication without a token"
    (let [request {}
          handler (wrap-authentication identity jws-backend)
          request' (handler request)]
      (is (not (authenticated? request')))
      (is (nil? (:identity request')))))

  (testing "Return 401 for JWS authorization with a wrong key"
    (let [request (make-jws-request jws-data "wrong-key")
          handler (-> (fn [_] (throw-unauthorized))
                      (wrap-authorization jws-backend)
                      (wrap-authentication jws-backend))
          response (handler request)]
      (is (= (:status response) 401))
      (is (= (:body response) "Unauthorized"))))

  (testing "Return 403 for an authenticated unauthorized JWS request"
    (let [request (make-jws-request {:userid 1} jws-secret)
          handler (-> (fn [_] (throw-unauthorized))
                      (wrap-authorization jws-backend)
                      (wrap-authentication jws-backend))
          response (handler request)]
      (is (= (:status response) 403))
      (is (= (:body response) "Permission denied"))))

  (testing "Call :unauthorized-handler for an unauthorized JWS request"
    (let [request (make-jws-request jws-data "wrong-key")
          onerror (fn [_ _] {:status 3000})
          backend (backends/jws {:secret jws-secret
                                 :unauthorized-handler onerror})
          handler (-> (fn [_] (throw-unauthorized))
                      (wrap-authorization backend)
                      (wrap-authentication backend))
          response (handler request)]
      (is (= (:status response) 3000))))

  (testing "Call on-error for invalid JWS token data"
    (let [request (make-jws-request jws-data "wrong-key")
          p (promise)
          onerror (fn [_ _] (deliver p true))
          backend (backends/jws {:secret jws-secret
                                 :on-error onerror})
          handler (-> identity
                      (wrap-authorization backend)
                      (wrap-authentication backend))
          response (handler request)]
      (is (deref p 1000 false))
      (is (= response request)))))

  (testing "Reject a wrong JWS token"
    (let [request (assoc (make-request "xyz")
                         :foo :bar)
          backend (backends/jws {:secret jws-secret})
          handler (-> identity
                      (wrap-authorization backend)
                      (wrap-authentication backend))
          _        (handler request)]
      (is (nil? (:identity request)))
      (is (= :bar (:foo request)))))

  (testing "Use a custom authfn with JWS"
    (let [request (make-jws-request jws-data jws-secret)
          handler (wrap-authentication identity jws-backend-with-authfn)
          request' (handler request)]
      (is (authenticated? request'))
      (is (= ::jws-authorized (:identity request'))))
  )

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Tests: JWE
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(def jwe-secret (hash/sha256 "mysupersecretkey"))
(def jwe-backend (backends/jwe {:secret jwe-secret}))
(def jwe-backend-with-authfn (backends/jwe {:secret jwe-secret :authfn (constantly ::jwe-authorized)}))
(def jwe-data {:userid 1})

(defn make-jwe-request
  [data secret]
  (let [header (->> (jwt/encrypt data secret)
                    (format "Token %s"))]
    {:headers {"authorization" header}}))

(deftest jwe-backend-test
  (testing "Authenticate with the JWE token backend"
    (let [request (make-jwe-request jwe-data jwe-secret)
          handler (wrap-authentication identity jwe-backend)
          request' (handler request)]
      (is (authenticated? request'))
      (is (= (:identity request') jwe-data))))

  (testing "Return nil for JWE authentication with a wrong key"
    (let [request (make-jwe-request jwe-data (hash/sha256 "wrong-key"))
          handler (wrap-authentication identity jwe-backend)
          request' (handler request)]
      (is (not (authenticated? request')))
      (is (nil? (:identity request')))))

  (testing "Return nil for JWE authentication without a token"
    (let [request {}
          handler (wrap-authentication identity jwe-backend)
          request' (handler request)]
      (is (not (authenticated? request')))
      (is (nil? (:identity request')))))

  (testing "Return 401 for JWE authorization with a wrong key"
    (let [request (make-jwe-request jwe-data (hash/sha256 "wrong-key"))
          handler (-> (fn [_] (throw-unauthorized))
                      (wrap-authorization jwe-backend)
                      (wrap-authentication jwe-backend))
          response (handler request)]
      (is (= (:status response) 401))))

  (testing "Return 403 for an authenticated unauthorized JWE request"
    (let [request (make-jwe-request {:userid 1} jwe-secret)
          handler (-> (fn [_] (throw-unauthorized))
                      (wrap-authorization jwe-backend)
                      (wrap-authentication jwe-backend))
          response (handler request)]
      (is (= (:status response) 403))))

  (testing "Call the unauthorized handler for an unauthorized JWE request"
    (let [request (make-jwe-request jwe-data (hash/sha256 "wrong-key"))
          onerror (fn [_ _] {:status 3000})
          backend (backends/jwe {:secret jwe-secret
                                 :unauthorized-handler onerror})
          handler (-> (fn [_] (throw-unauthorized))
                      (wrap-authorization backend)
                      (wrap-authentication backend))
          response (handler request)]
      (is (= (:status response) 3000))))

  (testing "Call on-error for invalid JWE token data"
    (let [request (make-jwe-request jws-data (hash/sha256 "foobar"))
          p (promise)
          onerror (fn [_ _] (deliver p true))
          backend (backends/jwe {:secret jwe-secret
                                 :on-error onerror})
          handler (-> identity
                      (wrap-authorization backend)
                      (wrap-authentication backend))
          response (handler request)]
      (is (deref p 1000 false))
      (is (= response request))))

  (testing "Use a custom authfn with JWE"
    (let [request (make-jwe-request jwe-data jwe-secret)
          handler (wrap-authentication identity jwe-backend-with-authfn)
          request' (handler request)]
      (is (authenticated? request'))
      (is (= ::jwe-authorized (:identity request')))))

  (testing "Propagate errors from a custom JWE authfn"
    (let [request (make-jwe-request jwe-data jwe-secret)
          backend (backends/jwe {:secret jwe-secret
                                 :authfn (fn [_]
                                           (throw (ex-info "JWE authfn failed" {})))})
          handler (wrap-authentication identity backend)]
      (is (thrown-with-msg? clojure.lang.ExceptionInfo
                            #"JWE authfn failed"
                            (handler request))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Tests: Token
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn token-authfn
  [_ token]
  (let [data {:token1 {:userid 1}
              :token2 {:userid 2}}]
    (get data (keyword token))))

(def backend (backends/token {:authfn token-authfn}))

(deftest token-backend-test
  (testing "Authenticate with the token backend"
    (let [request (make-request "token1")
          handler (wrap-authentication #(:identity %) backend)
          response (handler request)]
      (is (= response {:userid 1}))))

  (testing "Reject an invalid token"
    (let [request (make-request "token3")
          handler (wrap-authentication #(:identity %) backend)
          response (handler request)]
      (is (= response nil))))

  (testing "Handle an unauthorized token request"
    (let [request (make-request "token1")
          handler (-> (fn [_] (throw-unauthorized))
                      (wrap-authorization backend)
                      (wrap-authentication backend))
          response (handler request)]
      (is (= (:status response) 403))))

  (testing "Handle a second unauthorized token request"
    (let [request (make-request "token3")
          handler (-> (fn [_] (throw-unauthorized))
                      (wrap-authorization backend)
                      (wrap-authentication backend))
          response (handler request)]
      (is (= (:status response) 401))))

  (testing "Handle a third unauthorized token request"
    (let [request (make-request "token3")
          onerror (fn [_ _] {:status 3000})
          backend (backends/token {:authfn token-authfn
                                        :unauthorized-handler onerror})
          handler (-> (fn [_] (throw-unauthorized))
                      (wrap-authorization backend)
                      (wrap-authentication backend))
          response (handler request)]
        (is (= (:status response) 3000)))))

(deftest bearer-challenge-test
  (let [backend (backends/token {:authfn token-authfn
                                 :token-name "Bearer"
                                 :bearer-challenge true})]
    (testing "Add an RFC 6750 challenge to an unauthenticated 401 response"
      (let [request (make-request "token3")
            request (assoc-in request [:headers "authorization"] "Bearer token3")
            handler (-> (fn [_] (throw-unauthorized))
                        (wrap-authorization backend)
                        (wrap-authentication backend))
            response (handler request)]
        (is (= 401 (:status response)))
        (is (= "Bearer error=\"invalid_token\", error_description=\"The access token is invalid\""
               (get-in response [:headers "WWW-Authenticate"])))))

    (testing "Add an insufficient-scope challenge to an authenticated 403 response"
      (let [request {:headers {"authorization" "Bearer token1"}}
            handler (-> (fn [_] (throw-unauthorized))
                        (wrap-authorization backend)
                        (wrap-authentication backend))
            response (handler request)]
        (is (= 403 (:status response)))
        (is (= "Bearer error=\"insufficient_scope\", error_description=\"The request requires higher privileges than provided by the access token\""
               (get-in response [:headers "WWW-Authenticate"])))))

    (testing "Keep challenges disabled by default"
      (let [backend (backends/token {:authfn token-authfn :token-name "Bearer"})
            handler (-> (fn [_] (throw-unauthorized))
                        (wrap-authorization backend)
                        (wrap-authentication backend))
            response (handler (assoc-in (make-request "token3") [:headers "authorization"] "Bearer token3"))]
        (is (nil? (get-in response [:headers "WWW-Authenticate"])))))

    (testing "Do not alter a custom unauthorized handler"
      (let [backend (backends/token {:authfn token-authfn
                                     :token-name "Bearer"
                                     :bearer-challenge true
                                     :unauthorized-handler (fn [_ _] {:status 499 :headers {"X-Test" "ok"}})})
            request (assoc-in (make-request "token3") [:headers "authorization"] "Bearer token3")
            handler (-> (fn [_] (throw-unauthorized))
                        (wrap-authorization backend)
                        (wrap-authentication backend))
            response (handler request)]
        (is (= {:status 499 :headers {"X-Test" "ok"}} response))))))
