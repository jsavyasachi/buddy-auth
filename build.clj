(ns build
  (:refer-clojure :exclude [compile])
  (:require [clojure.string]
            [clojure.tools.build.api :as b]))

(def lib 'net.clojars.savya/buddy-auth)
(def version "3.2.1")
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
(defn- inject-provided-dep [pom-path]
  (let [dep (str "    <dependency>\n"
                 "      <groupId>net.clojars.savya</groupId>\n"
                 "      <artifactId>jose-clj</artifactId>\n"
                 "      <version>0.1.1</version>\n"
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
          :tag version}
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
