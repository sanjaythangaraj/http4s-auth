import cats.data.{Kleisli, OptionT}
import cats.effect.{ExitCode, IO, IOApp, Resource}
import org.http4s.*
import org.http4s.dsl.io.*
import org.http4s.implicits.*
import org.http4s.ember.server.*
import com.comcast.ip4s.*
import dev.profunktor.auth.JwtAuthMiddleware
import dev.profunktor.auth.jwt.{JwtAuth, JwtToken}
import io.circe.*
import io.circe.parser.*
import org.http4s.headers.{Authorization, Cookie}
import org.http4s.server.{AuthMiddleware, Router, Server}
import org.http4s.server.middleware.authentication.DigestAuth
import org.http4s.server.middleware.authentication.DigestAuth.Md5HashedAuthStore
import pdi.jwt.{JwtAlgorithm, JwtCirce, JwtClaim}

import java.nio.charset.StandardCharsets
import java.time.{Instant, LocalTime}
import java.util.Base64
import scala.util.Try

case class User(id: Long, name: String)

object BasicAuthDemo extends IOApp {
  val routes: HttpRoutes[IO] =
    HttpRoutes.of[IO] {
      case GET -> Root / "welcome" / user =>
        Ok(s"Welcome, ${user}")
    }

  // basic authentication
  // Request[IO] => IO[Either[String, User]]
  // Kleisli[IO, Request[IO], Either[String, User]]
  val basicAuthMethod: Kleisli[IO, Request[IO], Either[String, User]] = Kleisli { req =>
    val authHeader = req.headers.get[Authorization]
    authHeader match
      case Some(Authorization(BasicCredentials(creds))) => IO(Right(User(1L /* fetch from DB */, creds._1)))
      // password checking logic
      case Some(_) => IO(Left("No basic credentials"))
      case None => IO(Left("Unauthorized"))
  }

  // type AuthedRoutes[T, F[_]] = Kleisli[OptionT[F, *], AuthedRequest[F, T], Response[F]]
  val onFailure: AuthedRoutes[String, IO] = Kleisli { (req: AuthedRequest[IO, String]) =>
    OptionT.pure[IO](Response[IO](status = Status.Unauthorized))
  }

  // middleware
  val userBasicAuthMiddleware: AuthMiddleware[IO, User] = AuthMiddleware(basicAuthMethod, onFailure)

  val authRoutes = AuthedRoutes.of[User, IO] {
    case GET -> Root / "welcome" as user =>
      Ok(s"Welcome, ${user}") // business logic
  }

  val server = EmberServerBuilder
    .default[IO]
    .withHost(ipv4"0.0.0.0")
    .withPort(port"8080")
    .withHttpApp(userBasicAuthMiddleware(authRoutes).orNotFound)
    .build

  override def run(args: List[String]): IO[ExitCode] =
    server.use(_ => IO.never).as(ExitCode.Success)
}

object HttpDigestDemo extends IOApp.Simple {

  val searchFunc: String => IO[Option[(User, String)]] = {
    // query db for user and precomputed hash
    /*
      val searchFunc: String => IO[Option[(User, String)]] = username =>
          database.lookupUserAndHash(username).map {
            case Some((user, hash)) => Some(user, hash) // Hash from DB
            case None => None
          }
     */
    {
      case "daniel" =>
        for {
          user <- IO.pure(User(1L, "daniel"))
          hash <- Md5HashedAuthStore.precomputeHash[IO]("daniel", "http://localhost:8080", "rockthejvm")
          // hash = MD5(daniel:http://localhost:8080:rockthejvm)
        } yield Some(user, hash)
        // need to return IO(Some(User(1, Daniel), hash)
      case _ => IO.pure(None) // "user cannot be found"
    }
  }

  val authStore = Md5HashedAuthStore(searchFunc)
  val middleware: IO[AuthMiddleware[IO, User]] = DigestAuth.applyF[IO, User]("http://localhost:8080", authStore)

  val authRoutes = AuthedRoutes.of[User, IO] {
    case GET -> Root / "welcome" as user =>
      Ok(s"Welcome, ${user}") // business logic
  }

  val serverResource = for {
    mw <- Resource.eval(middleware)
    sv <- EmberServerBuilder
      .default[IO]
      .withHost(ipv4"0.0.0.0")
      .withPort(port"8080")
      .withHttpApp(mw(authRoutes).orNotFound)
      .build
  } yield sv



  override def run: IO[Unit] = serverResource.use(_ => IO.never).void
}

// 3 - sessions

/*
  1. user logs in with user/pass
  2. server replies with a Set-Cookie header
  3. user will send further HTTP requests with that cookie - server accepts or denies requests
 */
object HttpSessionDemo extends IOApp.Simple {

  def today: String = LocalTime.now().toString

  def getToken(username: String, date: String): String = Base64.getEncoder.encodeToString(s"$username:$date".getBytes(StandardCharsets.UTF_8))

  def getUsername(token: String): Option[String] = Try(new String(Base64.getDecoder.decode(token)).split(":")(0)).toOption

  // "login" endpoints
  val authRoutes = AuthedRoutes.of[User, IO] {
    case GET -> Root / "welcome" as user =>
      Ok(s"Welcome, ${user}").map(_.addCookie(ResponseCookie("sessioncookie", getToken(user.name, today), maxAge = Some(24 * 3600))))
  }

  // digest auth

  val searchFunc: String => IO[Option[(User, String)]] = {
    // query db for user and precomputed hash
    /*
      val searchFunc: String => IO[Option[(User, String)]] = username =>
          database.lookupUserAndHash(username).map {
            case Some((user, hash)) => Some(user, hash) // Hash from DB
            case None => None
          }
     */
    {
      case "daniel" =>
        for {
          user <- IO.pure(User(1L, "daniel"))
          hash <- Md5HashedAuthStore.precomputeHash[IO]("daniel", "http://localhost:8080", "rockthejvm")
          // hash = MD5(daniel:http://localhost:8080:rockthejvm)
        } yield Some(user, hash)
      // need to return IO(Some(User(1, Daniel), hash)
      case _ => IO.pure(None) // "user cannot be found"
    }
  }

  val authStore = Md5HashedAuthStore(searchFunc)
  val middleware: IO[AuthMiddleware[IO, User]] = DigestAuth.applyF[IO, User]("http://localhost:8080", authStore)

  // digest auth end

  def checkSessionCookie(cookie: Cookie): Option[RequestCookie] =
    cookie.values.toList.find(_.name == "sessioncookie")

  def modifyPath(username: String): Path =
    Uri.Path.unsafeFromString(s"statement/$username")

  def cookieCheckerApp(app: HttpRoutes[IO]): HttpRoutes[IO] = Kleisli { req =>
    val authHeader: Option[Cookie] = req.headers.get[Cookie]
    OptionT.liftF(
      authHeader.fold(ifEmpty = Ok("No cookies")) { cookie =>
        checkSessionCookie(cookie).fold(Ok("No token")) { requestCookie =>
          getUsername(requestCookie.content).fold(Ok("Invalid token")) { username =>
            if (req.pathInfo.renderString.startsWith("/statement")) {
              app.orNotFound.run(req.withPathInfo(modifyPath(username)))
            } else {
             app.orNotFound.run(req)
            }
          }
        }
      }
    )
  }

  val cookieAccessRoutes = HttpRoutes.of[IO] {
    case GET -> Root / "statement" / username =>
      Ok(s"Here is your financial statement $username")
    case GET -> Root / "logout" =>
      Ok("Logging out").map(_.removeCookie("sessioncookie"))
  }

  val routerResource = Resource.eval(middleware).map { mw =>
    Router(
      "/login" -> mw(authRoutes),
      "/" -> cookieCheckerApp(cookieAccessRoutes)
    )
  }

  val serverResource: Resource[IO, Server] = for {
    router <- routerResource
    server <- EmberServerBuilder
      .default[IO]
      .withHost(ipv4"0.0.0.0")
      .withPort(port"8080")
      .withHttpApp(router.orNotFound)
      .build
  } yield server

  override def run: IO[Unit] = serverResource.use(_ => IO.never).void
}

// 4 - JWT
object HttpJWTDemo extends IOApp.Simple {

  // "login" endpoints
  val authRoutes = AuthedRoutes.of[User, IO] {
    case GET -> Root / "welcome" as user =>
      Ok(s"Welcome, ${user}").map(_.addCookie(ResponseCookie("token", token)))
  }

  // digest auth

  val searchFunc: String => IO[Option[(User, String)]] = {
    // query db for user and precomputed hash
    /*
      val searchFunc: String => IO[Option[(User, String)]] = username =>
          database.lookupUserAndHash(username).map {
            case Some((user, hash)) => Some(user, hash) // Hash from DB
            case None => None
          }
     */
    {
      case "daniel" =>
        for {
          user <- IO.pure(User(1L, "daniel"))
          hash <- Md5HashedAuthStore.precomputeHash[IO]("daniel", "http://localhost:8080", "rockthejvm")
          // hash = MD5(daniel:http://localhost:8080:rockthejvm)
        } yield Some(user, hash)
      // need to return IO(Some(User(1, Daniel), hash)
      case _ => IO.pure(None) // "user cannot be found"
    }
  }

  val authStore = Md5HashedAuthStore(searchFunc)
  val middleware: IO[AuthMiddleware[IO, User]] = DigestAuth.applyF[IO, User]("http://localhost:8080", authStore)

  // digest auth end

  // JWT logic
  // claims

  case class TokenPayload(username: String, permsLevel: String)
  object TokenPayload {
    given decoder: Decoder[TokenPayload] = Decoder.instance { hCursor =>
      for {
        username <- hCursor.get[String]("user")
        permsLevel <- hCursor.get[String]("level")
      } yield TokenPayload(username, permsLevel)
    }
  }

  def claim(username: String, permsLevel: String) = JwtClaim(
    content =
      s"""
        |{
        | "user": "$username",
        | "level": "$permsLevel"
        |}
        |""".stripMargin,
    expiration = Some(Instant.now().plusSeconds(10 * 24 * 3600).getEpochSecond),
    issuedAt = Some(Instant.now().getEpochSecond)
  )

  val key = "tobeconfigured"
  val algo = JwtAlgorithm.HS256
  val token = JwtCirce.encode(claim("daniel", "basic"), key, algo)

  // "database"
  val database = Map(
    "daniel" -> User(1L, "daniel")
  )

  val authorizedFunction: JwtToken => JwtClaim => IO[Option[User]] =
    token => claim => decode[TokenPayload](claim.content) match {
      case Left(_) => IO(None)
      case Right(payload) => IO(database.get(payload.username))
    }

  val jwtMiddleware: AuthMiddleware[IO, User] = JwtAuthMiddleware[IO, User](JwtAuth.hmac(key, algo), authorizedFunction)

  val routerResource = Resource.eval(middleware).map { mw =>
    Router(
      "/login" -> mw(authRoutes),
      "/guarded" -> jwtMiddleware(guardedRoutes)
    )
  }

  // "login" endpoints
  val guardedRoutes = AuthedRoutes.of[User, IO] {
    case GET -> Root / "secret" as user => // user parsed from JWT
      Ok(s"THIS IS THE SECRET, $user")
  }

  val serverResource: Resource[IO, Server] = for {
    router <- routerResource
    server <- EmberServerBuilder
      .default[IO]
      .withHost(ipv4"0.0.0.0")
      .withPort(port"8080")
      .withHttpApp(router.orNotFound)
      .build
  } yield server

  override def run: IO[Unit] = serverResource.use(_ => IO.never).void
}