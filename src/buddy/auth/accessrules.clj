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

(ns buddy.auth.accessrules
  "Access rules system for Ring-based applications."
  (:require [buddy.auth :refer [throw-unauthorized]]
            [buddy.auth.http :as http]
            [clojure.walk :refer [postwalk]]
            [clout.core :as clout]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Rule Handler Protocol
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defprotocol IRuleHandlerResponse
  "Abstraction for uniform handling of rule handler return values.
  It has a default implementation for nil and Boolean types."
  (success? [_] "Check if a response is a success.")
  (get-value [_] "Get a handler response value."))

(extend-protocol IRuleHandlerResponse
  nil
  (success? [_] false)
  (get-value [_] nil)

  Boolean
  (success? [v] v)
  (get-value [_] nil))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Rule Handler Response Type
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(deftype RuleSuccess [v]
  IRuleHandlerResponse
  (success? [_] true)
  (get-value [_] v)

  Object
  (equals [_ other]
    (if (instance? RuleSuccess other)
      (= v (.-v ^RuleSuccess other))
      false))

  (toString [_]
    (with-out-str (print [v]))))

(deftype RuleError [v]
  IRuleHandlerResponse
  (success? [_] false)
  (get-value [_] v)

  Object
  (equals [_ other]
    (if (instance? RuleError other)
      (= v (.-v ^RuleError other))
      false))

  (toString [_]
    (with-out-str (print [v]))))

(alter-meta! #'->RuleSuccess assoc :private true)
(alter-meta! #'->RuleError assoc :private true)

(defn success
  "Return a success state from an access rule handler."
  ([] (RuleSuccess. nil))
  ([v] (RuleSuccess. v)))

(defn error
  "Return a failure state from an access rule handler."
  ([] (RuleError. nil))
  ([v] (RuleError. v)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Implementation
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn compile-rule-handler
  "Receive a rule handler and return its compiled version.

  The compiled rule handler is a function. It accepts a request as its first
  parameter and returns its evaluation result.

  The rule can be a function or a logical expression. Use a hash map for a
  logical expression:

      {:or [f1 f2]}
      {:and [f1 f2]}

  You can nest logical expressions:

      {:or [f1 {:and [f2 f3]}]}

  A rule handler must return `success` or `error`. `success` marks a handler
  that passes validation. `error` marks a rule that does not pass validation.

  An error mark can return a Ring response to the HTTP client. It can return a
  string message to an `on-error` handler. If no handler exists, it returns a
  bad-request response with the message as its body.

  Example of success marks:

  - `true`
  - `(success)`

  Example of error marks:

  - `nil`
  - `false`
  - `(error \"Error msg\")`
  - `(error {:status 400 :body \"Unauthorized\"})`
  "
  [rule]
  (postwalk (fn [form]
              (cond
               ;; This form is a handler.
               (fn? form)
               (fn [req] (form req))

               (:or form)
               (fn [req]
                 (let [rules (:or form)
                       evals (map (fn [x] (x req)) rules)
                       accepts (filter success? evals)]
                   (if (seq accepts)
                     (first accepts)
                     (last evals))))

               (:and form)
               (fn [req]
                 (let [rules (:and form)
                       evals (map (fn [x] (x req)) rules)
                       rejects (filter (complement success?) evals)]
                   (if (seq rejects)
                     (first rejects)
                     (first evals))))

               :else form))
            rule))

(defn- matches-request-method
  "Match the :request-method of `request` against `allowed` HTTP methods.
  `allowed` can be a keyword, a set of keywords, or nil."
  [request allowed]
  (let [actual (:request-method request)]
    (cond
      (keyword? allowed)
      (= actual allowed)

      (set? allowed)
      (or (empty? allowed)
          (contains? allowed actual))

      :else true)))

(defn  compile-access-rule
  "Receive an access rule and return its compiled version.

  An uncompiled access rule is a hash map with `:uri` and `:handler` keys.
  `:uri` uses URL match syntax. `:handler` is a rule handler.

  Example access rules:

      [{:uri \"/foo\"
        :handler user-access}
       {:uris [\"/bar\" \"/baz\"]
        :handler admin-access}]

  The clout library (https://github.com/weavejester/clout) matches the `:uri`.

  It also supports regular expressions. They match the full request URI:

      [{:pattern #\"^/foo$\"
        :handler user-access}

  An access rule can also match HTTP methods with `:request-method`.
  `:request-method` can be a keyword or a set of keywords.

      [{:pattern #\"^/foo$\"
        :handler user-access
        :request-method :get}

  Compilation changes the uncompiled access rule to avoid overhead during
  request processing.

  The compiled access rule has a similar format. Its `:handler` is compiled.
  A matcher function replaces `:pattern` or `:uri`.

  Example compiled access rule:

      [{:matcher #<accessrules$compile_access_rule$fn__13092$fn__13095...>
        :handler #<accessrules$compile_rule_handler$fn__14040$fn__14043...>
  "
  [accessrule]
  {:pre [(map? accessrule)]}
  (let [request-method (:request-method accessrule)
        handler (compile-rule-handler (:handler accessrule))
        matcher (cond
                  (:pattern accessrule)
                  (fn [request]
                    (let [pattern (:pattern accessrule)
                          uri (:uri request)]
                      (when (and (matches-request-method request request-method)
                                 (seq (re-matches pattern uri)))
                        {})))

                  (:uri accessrule)
                  (let [route (clout/route-compile (:uri accessrule))]
                    (fn [request]
                      (let [match-params (clout/route-matches route request)]
                        (when (and (matches-request-method request request-method) match-params)
                          match-params))))

                  (:uris accessrule)
                  (let [routes (mapv clout/route-compile (:uris accessrule))]
                    (fn [request]
                      (let [match-params (->> (map #(clout/route-matches % request) routes)
                                              (filter identity)
                                              (first))]
                        (when (and (matches-request-method request request-method) match-params)
                          match-params))))

                  :else (fn [_] {}))]
    (assoc accessrule
           :matcher matcher
           :handler handler)))

(defn compile-access-rules
  "Compile a list of access rules.

  See the `compile-access-rule` docstring for more information."
  [accessrules]
  (mapv compile-access-rule accessrules))

(defn- match-access-rules
  "Iterate over access rules and match each rule in order.
  Return the first matching access rule or nil."
  [accessrules request]
  (reduce (fn [_ accessrule]
            (let [matcher (:matcher accessrule)
                  match-result (matcher request)]
              (when match-result
                (reduced (assoc accessrule :match-params match-result)))))
          nil
          accessrules))

(defn handle-error
  "Handle errors when `wrap-access-rules` middleware evaluates access rules.

  It receives a handler response, a request, and a hash map passed to the
  access rule definition.

  The response must satisfy the IRuleHandlerResponse protocol."
  {:no-doc true}
  ([response request {:keys [reject-handler on-error redirect]}]
   {:pre [(satisfies? IRuleHandlerResponse response)]}
   (let [val (get-value response)]
     (cond
       (string? redirect)
       (http/redirect redirect)

       (fn? on-error)
       (on-error request val)

       (http/response? val)
       val

       (fn? reject-handler)
       (reject-handler request val)

       (string? val)
       (http/response val 400)

       :else
       (throw-unauthorized))))
  ([response request rule respond raise]
   (try
     (let [err (handle-error response request rule)]
       (respond err))
     (catch Exception e
       (raise e)))))

(defn- apply-matched-access-rule
  "Run the rule handler of an access rule and return its result."
  [match request]
  {:pre [(map? match)
         (contains? match :handler)]}
  (let [handler (:handler match)
        params  (:match-params match)]
    (-> request
        (assoc :match-params params)
        (handler))))

(defn wrap-access-rules
  "Ring middleware that defines access rules for a Ring handler.

  `wrap-access-rules` middleware expects an access rules list like this:

      [{:uri \"/foo/*\"
        :handler user-access}
       {:uri \"/bar/*\"
        :handler {:or [user-access admin-access]}}
       {:uri \"/baz/*\"
        :handler {:and [user-access {:or [admin-access operator-access]}]}}]

  The middleware evaluates access rules in order. It stops when it finds a match.

  See the `compile-rule-handler` docstring for rule handler information."
  [handler & [{:keys [policy rules] :or {policy :allow} :as opts}]]
  (when (nil? rules)
    (throw (IllegalArgumentException. "rules should not be empty.")))
  (let [accessrules (compile-access-rules rules)]
    (fn
      ([request]
       (if-let [match (match-access-rules accessrules request)]
         (let [res (apply-matched-access-rule match request)]
           (if (success? res)
             (handler request)
             (handle-error res request (merge opts match))))
         (case policy
           :allow (handler request)
           :reject (handle-error (error nil) request opts))))
      ([request respond raise]
       (if-let [match (match-access-rules accessrules request)]
         (let [res (apply-matched-access-rule match request)]
           (if (success? res)
             (handler request respond raise)
             (handle-error res request (merge opts match) respond raise)))
         (case policy
           :allow (handler request respond raise)
           :reject (handle-error (error nil) request opts respond raise)))))))

(defn restrict
  "Like `wrap-access-rules` middleware, but it works as a decorator.
  Use it with the compojure routing library or a similar library. Example:

      (defn login-ctrl [req] ...)
      (defn admin-ctrl [req] ...)

      (defroutes app
        (ANY \"/login\" [] login-ctrl)
        (GET \"/admin\" [] (restrict admin-ctrl {:handler admin-access ;; Mandatory
                                                 :on-error my-reject-handler)

  This decorator uses the same access rules without a URL matching algorithm.
  It couples router code with access rules."
  [handler rule]
  (let [match (compile-access-rule rule)]
    (fn
      ([request]
       (let [rsp (apply-matched-access-rule match request)]
         (if (success? rsp)
           (handler request)
           (handle-error rsp request rule))))
      ([request respond raise]
       (let [rsp (apply-matched-access-rule match request)]
         (if (success? rsp)
           (handler request respond raise)
           (handle-error rsp request rule respond raise)))))))
