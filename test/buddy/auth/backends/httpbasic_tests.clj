(ns buddy.auth.backends.httpbasic-tests
  (:require [clojure.test :refer :all]
            [buddy.core.codecs :refer :all]
            [buddy.core.codecs.base64 :as b64]
            [buddy.auth :refer [throw-unauthorized]]
            [buddy.auth.http :as http]
            [buddy.auth.backends :as backends]
            [buddy.auth.backends.httpbasic :as httpbasic]
            [buddy.auth.middleware :refer [wrap-authentication wrap-authorization]]))

(defn make-header
  [username password]
  (format "Basic %s" (-> (b64/encode (format "%s:%s" username password))
                         (bytes->str))))

(defn make-request
  ([] {:headers {}})
  ([username password]
   (let [auth (make-header username password)]
     {:headers {"auThorIzation" auth "lala" "2"}})))

(defn auth-fn
  [request {:keys [username]}]
  (if (= username "foo")
    :valid
    nil))

(def backend
  (backends/http-basic
   {:authfn auth-fn :realm "Foo"}))

(deftest httpbasic-parse-test
  (testing "Parse an HTTP Basic header from a request"
    (let [parse #'httpbasic/parse-header
          request (make-request "foo" "bar")
          parsed  (parse request)]
      (is (not (nil? parsed)))
      (is (= (:password parsed) "bar"))
      (is (= (:username parsed) "foo"))))
  (testing "Parse an HTTP Basic header with a colon in the password"
    (let [parse #'httpbasic/parse-header
          request (make-request "foo" "bar:baz")
          parsed  (parse request)]
      (is (not (nil? parsed)))
      (is (= (:password parsed) "bar:baz"))
      (is (= (:username parsed) "foo")))))

(deftest httpbasic-auth-backend
  (testing "Authenticate an anonymous request"
    (let [handler (wrap-authentication identity backend)
          request (make-request)
          response (handler request)]
      (is (= (:identity response) nil))))

  (testing "Reject an invalid request"
    (let [handler (wrap-authentication identity backend)
          request (make-request "test" "test")
          response (handler request)]
      (is (nil? (:identity response)))))

  (testing "Authenticate a request"
    (let [handler (wrap-authentication identity backend)
          request (make-request "foo" "bar")
          response (handler request)]
      (is (= (:identity response) :valid))))

  (testing "Return 401 for an unauthenticated request"
    (let [handler (-> (fn [req] (if (nil? (:identity req))
                                  (throw-unauthorized {:msg "FooMsg"})
                                  req))
                      (wrap-authorization backend)
                      (wrap-authentication backend))
          request (make-request "user" "pass")
          response (handler request)]
      (is (= (:status response) 401))
      (is (= (:body response) "Unauthorized"))))

  (testing "Use an HTTP Basic backend for authorization"
    (let [handler (-> (fn [req] (if (nil? (:identity req))
                                  (throw-unauthorized {:msg "FooMsg"})
                                  req))
                      (wrap-authorization backend)
                      (wrap-authentication backend))
          request (make-request "foo" "pass")
          response (handler request)]
      (is (= (:identity response) :valid))))

  (testing "Return 403 for an authenticated unauthorized request"
    (let [handler (-> (fn [req] (throw-unauthorized {:msg "FooMsg"}))
                      (wrap-authorization backend)
                      (wrap-authentication backend))
          request (make-request "foo" "pass")
          response (handler request)]
      (is (= (:status response) 403)))))
