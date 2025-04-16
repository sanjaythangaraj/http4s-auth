import scala.collection.Seq

ThisBuild / version := "0.1.0-SNAPSHOT"

ThisBuild / scalaVersion := "3.3.5"

lazy val root = (project in file("."))
  .settings(
    name := "http4s-auth"
  )

libraryDependencies ++= Seq(
  "org.http4s" %% "http4s-ember-server" % "0.23.30",
  "org.http4s" %% "http4s-dsl" % "0.23.30",
  "dev.profunktor" %% "http4s-jwt-auth" % "2.0.4",
  "com.github.jwt-scala" %% "jwt-core" % "10.0.4",
  "com.github.jwt-scala" %% "jwt-circe" % "10.0.4",
  "org.typelevel" %% "log4cats-slf4j" % "2.7.0",
  "org.slf4j" % "slf4j-simple" % "2.0.17"
)

