(ns build
  (:refer-clojure :exclude [compile])
  (:require [clojure.tools.build.api :as b]))

(def lib 'net.clojars.savya/buddy-auth)
(def version "3.2.0")
(def class-dir "target/classes")
(def basis (b/create-basis {:project "deps.edn"}))
(def jar-file (format "target/%s-%s.jar" (name lib) version))

(defn clean [_]
  (b/delete {:path "target"}))

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

  (b/copy-dir
   {:src-dirs ["src" "resources"]
    :target-dir class-dir})

  (b/jar
   {:class-dir class-dir
    :jar-file jar-file}))
