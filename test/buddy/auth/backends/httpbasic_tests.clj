(ns buddy.auth.backends.httpbasic-tests
  (:require [clojure.test :refer [deftest is testing]]
            [buddy.core.codecs :refer [bytes->str]]
            [buddy.core.codecs.base64 :as b64]
            [buddy.auth :refer [throw-unauthorized]]
            [buddy.auth.backends :as backends]
            [buddy.auth.backends.httpbasic :as httpbasic]
            [buddy.auth.middleware :refer [wrap-authentication wrap-authorization]]
            [clojure.string :as str]
            [clojure.test.check :as tc]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]))

(set! *warn-on-reflection* true)

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
  [_ {:keys [username]}]
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

(defn parse-header
  [header]
  ((deref #'httpbasic/parse-header) {:headers {"authorization" header}}))

(def malformed-header-gen
  (gen/one-of
   [(gen/elements [nil "" " " "\t\n"])
    (gen/fmap #(str % " payload")
             (gen/such-that seq gen/string-alphanumeric))
    (gen/elements ["Basic" "Basic " "Basic !!!" "Basic ==" "Basic a" "Basic a==="])]))

(deftest malformed-http-basic-headers-are-clean
  (let [result (tc/quick-check
                100
                (prop/for-all [header malformed-header-gen]
                  (let [parsed (try
                                 (parse-header header)
                                 (catch IllegalArgumentException _ ::invalid-base64)
                                 (catch Throwable error error))]
                    (and (not (instance? Throwable parsed))
                         (if (and (string? header)
                                  (str/starts-with? header "Basic ")
                                  (not= parsed ::invalid-base64))
                           (or (nil? parsed)
                               (= {:username "" :password nil} parsed))
                           true)))))]
    (is (= true (:pass? result)) (pr-str result))))

(def basic-char-gen
  (gen/elements [\a \Z \0 \9 \space \: \. \* \+ \? \( \) \[ \] \{ \} \u00e9 \u65e5 \u0436]))

(def basic-string-gen
  (gen/fmap #(apply str %)
            (gen/vector basic-char-gen 0 24)))

(defn expected-basic-credentials
  [username password]
  (let [separator (.indexOf ^String username ":")]
    (if (neg? separator)
      {:username username :password password}
      {:username (subs username 0 separator)
       :password (str (subs username (inc separator)) ":" password)})))

(deftest unusual-basic-credentials-follow-basic-format
  (let [result (tc/quick-check
                100
                (prop/for-all [username basic-string-gen
                               password basic-string-gen]
                  (= (expected-basic-credentials username password)
                     (parse-header (make-header username password)))))]
    (is (= true (:pass? result)) (pr-str result))))

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
    (let [handler (-> (fn [_] (throw-unauthorized {:msg "FooMsg"}))
                      (wrap-authorization backend)
                      (wrap-authentication backend))
          request (make-request "foo" "pass")
          response (handler request)]
      (is (= (:status response) 403)))))
