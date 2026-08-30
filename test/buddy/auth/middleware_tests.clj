(ns buddy.auth.middleware-tests
  (:require [clojure.test :refer [deftest is testing]]
            [buddy.auth :refer [throw-unauthorized]]
            [buddy.auth.protocols :as proto]
            [buddy.auth.middleware :as mw]))

(set! *warn-on-reflection* true)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Authentication middleware tests
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn auth-backend
  [secret token-name]
  (reify
    proto/IAuthentication
    (-parse [_ request]
      (get request token-name))

    (-authenticate [_ _ data]
      (assert data)
      (when (= data secret)
        :valid))))

(defn- async-identity [req respond _]
  (respond req))

(deftest wrap-authentication
  (testing "Authenticate requests"
    (let [handler (mw/wrap-authentication identity (auth-backend ::ok ::authdata))
          response (handler {::authdata ::ok})]
      (is (= (:identity response) :valid))
      (is (= (::authdata response) ::ok))))

  (testing "Authenticate asynchronous requests"
    (let [handler (-> async-identity
                      (mw/wrap-authentication (auth-backend ::ok ::authdata)))
          response (promise)
          exception (promise)]
      (handler {::authdata ::ok} response exception)
      (is (= (:identity @response) :valid))
      (is (= (::authdata @response) ::ok))
      (is (not (realized? exception)))))

  (testing "Process an anonymous request"
    (let [handler (mw/wrap-authentication identity (auth-backend ::ok ::authdata))
          response (handler {})]
      (is (= (:identity response) nil))
      (is (= (::authdata response) nil))))

  (testing "Process an anonymous asynchronous request"
    (let [handler (-> async-identity
                      (mw/wrap-authentication (auth-backend ::ok ::authdata)))
          response (promise)
          exception (promise)]
      (handler {} response exception)
      (is (= (:identity @response) nil))
      (is (= (::authdata @response) nil))
      (is (not (realized? exception)))))

  (testing "Reject an invalid request"
    (let [handler (mw/wrap-authentication identity (auth-backend ::ok ::authdata))
          response (handler {::authdata ::fake})]
      (is (nil? (:identity response)))
      (is (= (::authdata response) ::fake))))

  (testing "Reject an invalid asynchronous request"
    (let [handler (-> async-identity
                      (mw/wrap-authentication (auth-backend ::ok ::authdata)))
          response (promise)
          exception (promise)]
      (handler {::authdata ::fake} response promise)
      (is (nil? (:identity @response)))
      (is (= (::authdata @response) ::fake))
      (is (not (realized? exception))))))

(deftest wrap-authentication-with-multiple-backends
  (let [backends [(auth-backend ::ok-1 ::authdata)
                  (auth-backend ::ok-2 ::authdata2)]
        handler (apply mw/wrap-authentication identity backends)
        async-handler (apply mw/wrap-authentication async-identity backends)]

    (testing "Use backend #1"
      (let [response (handler {::authdata ::ok-1})]
        (is (= (:identity response) :valid))
        (is (= (::authdata response) ::ok-1))))

    (testing "Use backend #1 for asynchronous requests"
      (let [response (promise)
            exception (promise)]
        (async-handler {::authdata ::ok-1} response exception)
        (is (= (:identity @response) :valid))
        (is (= (::authdata @response) ::ok-1))
        (is (not (realized? exception)))))

    (testing "Use backend #2"
      (let [response (handler {::authdata2 ::ok-2})]
        (is (= (:identity response) :valid))
        (is (= (::authdata2 response) ::ok-2))))

    (testing "Use backend #2 for asynchronous requests"
      (let [response (promise)
            exception (promise)]
        (async-handler {::authdata2 ::ok-2} response exception)
        (is (= (:identity @response) :valid))
        (is (= (::authdata2 @response) ::ok-2))
        (is (not (realized? exception)))))

    (testing "Process a request with no backends"
      (let [response (handler {::authdata ::fake})]
        (is (nil? (:identity response)))
        (is (= (::authdata response) ::fake))))

    (testing "Process an asynchronous request with no backends"
      (let [response (promise)
            exception (promise)]
        (async-handler {::authdata ::fake} response exception)
        (is (nil? (:identity @response)))
        (is (= (::authdata @response) ::fake))
        (is (not (realized? exception)))))

    (testing "Call the handler exactly once"
      (let [state (atom 0)
            counter (fn [request] (swap! state inc) request)
            handler (apply mw/wrap-authentication counter backends)
            response (handler {::authdata ::fake})]
        (is (nil? (:identity response)))
        (is (= (::authdata response) ::fake))
        (is (= @state 1))))

    (testing "Call the asynchronous handler exactly once"
      (let [state (atom 0)
            counter (fn [request respond _]
                      (swap! state inc)
                      (respond request))
            handler (apply mw/wrap-authentication counter backends)
            response (promise)
            exception (promise)]
        (handler {::authdata ::fake} response exception)
        (is (nil? (:identity @response)))
        (is (= (::authdata @response) ::fake))
        (is (= @state 1))
        (is (not (realized? exception)))))

    (testing "Use zero backends"
      (let [request {:uri "/"}]
        (is (= ((mw/wrap-authentication identity) request) request))))

    (testing "Use zero backends for asynchronous requests"
      (let [request {:uri "/"}
            response (promise)
            exception (promise)]
        ((mw/wrap-authentication async-identity) request response exception)
        (is (= @response request))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Authorization middleware tests
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(def autz-backend
  (reify
    proto/IAuthorization
    (-handle-unauthorized [_ _ data]
      {:body "error" :status 401 :data data})))

(defn- custom-authorization-error
  "An exception that carries its own error data through IAuthorizationdError.

  `proxy` implements the protocol's generated interface directly, so the method
  must be written under its munged Java name (`_get_error_data`) and without an
  explicit `this` parameter. Spelling it `-get-error-data` here compiles but
  never overrides anything."
  [data]
  (proxy [Exception buddy.auth.protocols.IAuthorizationdError] []
    (_get_error_data [] data)))

(deftest wrap-authorization
  (testing "Authorize a request"
    (let [handler (mw/wrap-authorization identity autz-backend)
          response (handler {:foo :bar})]
      (is (= (:foo response) :bar))))

  (testing "Authorize an asynchronous request"
    (let [handler (mw/wrap-authorization async-identity autz-backend)
          response (promise)
          exception (promise)]
      (handler {:foo :bar} response exception)
      (is (= (:foo @response) :bar))
      (is (not (realized? exception)))))

  (testing "Reject an unauthorized request"
    (let [handler (fn [_]
                    (throw-unauthorized {:foo :bar}))
          handler (mw/wrap-authorization handler autz-backend)
          response (handler {})]
      (is (= (:body response) "error"))
      (is (= (:status response) 401))
      (is (= (:data response) {:foo :bar}))))

  (testing "Reject an unauthorized asynchronous request"
    (let [handler (fn [_ _ _]
                    (throw-unauthorized {:foo :bar}))
          handler (mw/wrap-authorization handler autz-backend)
          response (promise)
          exception (promise)]
      (handler {} response exception)
      (is (= (:body @response) "error"))
      (is (= (:status @response) 401))
      (is (= (:data @response) {:foo :bar}))
      (is (not (realized? exception)))))

  (testing "Reject an unauthorized exception raised asynchronously"
    (let [raised (promise)
          handler (fn [_ _ raise]
                    (deliver raised raise))
          handler (mw/wrap-authorization handler autz-backend)
          response (promise)
          exception (promise)]
      (handler {} response exception)
      (deref (future (try
                       (throw-unauthorized {:foo :bar})
                       (catch Exception e
                         (@raised e)))
                     ) 100 ::timeout)
      (is (= {:body "error" :status 401 :data {:foo :bar}}
             (deref response 100 ::timeout)))
      (is (not (realized? exception)))))

  (testing "Reject an unauthorized request carrying its own error data"
    (let [error (custom-authorization-error {:foo :bar})]
      (is (satisfies? proto/IAuthorizationdError error))
      (let [handler (mw/wrap-authorization (fn [_] (throw error)) autz-backend)]
        (is (= {:body "error" :status 401 :data {:foo :bar}}
               (handler {}))))))

  (testing "Reject an asynchronous request carrying its own error data"
    (let [handler (fn [_ _ _]
                    (throw (custom-authorization-error {:foo :bar})))
          handler (mw/wrap-authorization handler autz-backend)
          response (promise)
          exception (promise)]
      (handler {} response exception)
      (is (= {:body "error" :status 401 :data {:foo :bar}}
             (deref response 100 ::timeout)))
      (is (not (realized? exception)))))

  (testing "Reject an error data exception raised asynchronously"
    (let [raised (promise)
          handler (fn [_ _ raise] (deliver raised raise))
          handler (mw/wrap-authorization handler autz-backend)
          response (promise)
          exception (promise)]
      (handler {} response exception)
      (deref (future (@raised (custom-authorization-error {:foo :bar}))) 100 ::timeout)
      (is (= {:body "error" :status 401 :data {:foo :bar}}
             (deref response 100 ::timeout)))
      (is (not (realized? exception)))))

  (testing "An exception without error data is rethrown"
    (let [handler (mw/wrap-authorization
                   (fn [_] (throw (IllegalStateException. "boom")))
                   autz-backend)]
      (is (thrown-with-msg? IllegalStateException #"boom" (handler {})))))

  (testing "Reject an unauthorized request with a function backend"
    (let [backend (fn [_ data] {:body "error" :status 401 :data data})
          handler (fn [_]
                    (throw-unauthorized {:foo :bar}))
          handler (mw/wrap-authorization handler backend)
          response (handler {})]
      (is (= (:body response) "error"))
      (is (= (:status response) 401))
      (is (= (:data response) {:foo :bar}))))

  (testing "Reject an unauthorized asynchronous request with a function backend"
    (let [backend (fn [_ data] {:body "error" :status 401 :data data})
          handler (fn [_ _ _]
                    (throw-unauthorized {:foo :bar}))
          handler (mw/wrap-authorization handler backend)
          response (promise)
          exception (promise)]
      (handler {} response exception)
      (is (= (:body @response) "error"))
      (is (= (:status @response) 401))
      (is (= (:data @response) {:foo :bar}))
      (is (not (realized? exception))))))
