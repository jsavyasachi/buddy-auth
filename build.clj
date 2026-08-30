(ns build
  (:refer-clojure :exclude [compile])
  (:require [clojure.edn :as edn]
            [clojure.string]
            [clojure.tools.build.api :as b]
            [deps-deploy.deps-deploy :as dd]))

(def lib 'net.clojars.savya/buddy-auth)
(def version "4.1.0")
(def class-dir "target/classes")
(def basis (b/create-basis {:project "deps.edn"}))
(def jar-file (format "target/%s-%s.jar" (name lib) version))

(defn clean [_]
  (b/delete {:path "target"}))

;; The `jwks` backend requires jose-clj at compile time but not at runtime for
;; users who don't use it, so jose-clj is not a normal (compile-scope, transitive)
;; dependency. Declaring it `provided` keeps it off consumers' transitive
;; classpath while still putting it on cljdoc's analysis classpath, so the
;; buddy.auth.backends.jwks namespace loads during doc generation.
;;
;; The version is read from deps.edn (jose-clj is declared under :deps and/or
;; several aliases, e.g. :dev and :test) instead of being hardcoded here, so
;; the POM can't drift out of sync with the version the code is actually
;; developed and tested against. Every declared version is collected and
;; checked for agreement: a missing or conflicting declaration is a build
;; error, not a silently wrong or blank POM entry.
(defn- jose-clj-version []
  (let [deps-map (edn/read-string (slurp "deps.edn"))
        versions (->> deps-map
                      (tree-seq coll? seq)
                      (filter map?)
                      (keep #(get-in % ['net.clojars.savya/jose-clj :mvn/version]))
                      distinct)]
    (case (count versions)
      0 (throw (ex-info "jose-clj version not found in deps.edn" {:deps-edn deps-map}))
      1 (first versions)
      (throw (ex-info "jose-clj versions disagree across deps.edn" {:versions versions})))))

(defn- inject-provided-dep [pom-path]
  (let [dep (str "    <dependency>\n"
                 "      <groupId>net.clojars.savya</groupId>\n"
                 "      <artifactId>jose-clj</artifactId>\n"
                 "      <version>" (jose-clj-version) "</version>\n"
                 "      <scope>provided</scope>\n"
                 "    </dependency>\n  </dependencies>")
        pom (slurp pom-path)]
    (spit pom-path (clojure.string/replace-first pom "  </dependencies>" dep))))

(defn jar [_]
  (b/write-pom
   {:class-dir class-dir
    :lib lib
    :version version
    :basis basis
    :src-dirs ["src"]
    :scm {:url "https://github.com/jsavyasachi/buddy-auth"
          :tag (str "v" version)}
    :pom-data [[:licenses
                [:license
                 [:name "Apache License 2.0"]
                 [:url "https://www.apache.org/licenses/LICENSE-2.0"]]]]})

  (inject-provided-dep (b/pom-path {:lib lib :class-dir class-dir}))

  (b/copy-dir
   {:src-dirs ["src" "resources"]
    :target-dir class-dir})

  (b/jar
   {:class-dir class-dir
    :jar-file jar-file}))

(defn deploy [_]
  (jar nil)
  (dd/deploy {:installer :remote
              :artifact jar-file
              :pom-file (b/pom-path {:lib lib :class-dir class-dir})}))
