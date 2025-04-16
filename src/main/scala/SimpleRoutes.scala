import cats.data.{Kleisli, OptionT}
import cats.effect.{ExitCode, IO, IOApp}
import org.http4s.*
import org.http4s.dsl.io.*
import org.http4s.implicits.*
import org.http4s.ember.server.*
import com.comcast.ip4s.*
import org.http4s.headers.Authorization
import org.http4s.server.AuthMiddleware

case class User(id: Long, name: String)

object SimpleRoutes extends IOApp {
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
