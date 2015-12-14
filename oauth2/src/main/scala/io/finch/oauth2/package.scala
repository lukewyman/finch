package io.finch

import cats.Eval
import com.twitter.finagle.OAuth2
import com.twitter.finagle.http.Status
import com.twitter.finagle.oauth2.{AuthInfo, DataHandler, GrantHandlerResult, OAuthError}

package object oauth2 {

  private[this] object oa2 extends OAuth2
  private[this] val handleOAuthError: PartialFunction[Throwable, Output[Nothing]] = {
    case e: OAuthError =>
      val bearer = Seq("error=\"" + e.errorType + "\"") ++
        (if (!e.description.isEmpty) Seq("error_description=\"" + e.description + "\"") else Nil)

      Output.failure(e, Status(e.statusCode))
        .withHeader("WWW-Authenticate" -> s"Bearer ${bearer.mkString(", ")}")
  }

  def authorize[U](dataHandler: DataHandler[U]): Endpoint[AuthInfo[U]] =
    Endpoint.embed(items.MultipleItems)(i =>
      Some((i, Eval.now(oa2.authorize(i.request, dataHandler).map(ai => Output.payload(ai)))))
    ).handle(handleOAuthError)

  def issueAccessToken[U](dataHandler: DataHandler[U]): Endpoint[GrantHandlerResult] =
    Endpoint.embed(items.MultipleItems)(i =>
      Some((i, Eval.now(oa2.issueAccessToken(i.request, dataHandler).map(t => Output.payload(t)))))
    ).handle(handleOAuthError)
}
