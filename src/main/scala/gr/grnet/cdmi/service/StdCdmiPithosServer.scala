/*
 * Copyright (C) 2010-2014 GRNET S.A.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package gr.grnet.cdmi.service

import java.net.URL
import java.nio.charset.StandardCharsets
import java.util.Locale

import com.fasterxml.jackson.databind.node.JsonNodeType
import com.google.common.cache.{CacheBuilder, CacheLoader}
import com.twitter.app.{App, GlobalFlag}
import com.twitter.finagle.httpx.{RequestBuilder, Status}
import com.twitter.io.Buf
import com.twitter.logging.{Level, Logging}
import com.twitter.util._
import gr.grnet.cdmi.metadata.StorageSystemMetadata
import gr.grnet.cdmi.model.{ContainerModel, Model, ObjectModel}
import gr.grnet.common.http.{StdHeader, StdMediaType, TResult}
import gr.grnet.common.io.Base64
import gr.grnet.common.json.Json
import gr.grnet.common.text.{ParentPath, RemovePrefix}
import gr.grnet.pithosj.api.PithosApi
import gr.grnet.pithosj.core.ServiceInfo
import gr.grnet.pithosj.core.command.{CheckExistsObjectResultData, GetObject2ResultData}
import gr.grnet.pithosj.impl.finagle.{FinagleClientFactory, PithosClientFactory}

import scala.collection.immutable.Seq

object pithosTimeout extends GlobalFlag[Long](
                              1000L * 60L * 3L /* 3 min*/,
                              "millis to wait for Pithos response")

object pithosServerURL extends GlobalFlag[String](
                                "https://pithos.okeanos.grnet.gr",
                                "Pithos server URL")

object pithosRootPath extends GlobalFlag[String](
                                "/object-store/v1",
                                "Pithos service root path prefix. All Pithos requests have this prefix")

object pithosUUID    extends GlobalFlag[String](
                              "",
                              "Pithos (Astakos) UUID. Usually set for debugging")

object pithosToken   extends GlobalFlag[String](
                              "",
                              "Pithos (Astakos) Token. Set this only for debugging")

object authURL       extends GlobalFlag[String](
                              "https://okeanos-occi2.hellasgrid.gr:5000/main",
                              "auth proxy")

object authRedirect  extends GlobalFlag[Boolean](
                              true,
                              "Redirect to 'authURL' if token is not present (in an attempt to get one)")

object tokensURL     extends GlobalFlag[String](
                              "https://accounts.okeanos.grnet.gr/identity/v2.0/tokens",
                              "Used to obtain UUID from token")

/**
 * A Pithos-based implementation for the CDMI service
 *
 * @author Christos KK Loverdos <loverdos@gmail.com>
 */
object StdCdmiPithosServer extends CdmiRestService
  with App with Logging
  with CdmiRestServiceTypes
  with CdmiRestServiceHandlers
  with CdmiRestServiceMethods
  with CdmiRestServiceResponse {
  
  override def defaultLogLevel: Level = Level.DEBUG

  final val X_Pithos_Server_URL = "X-Pithos-Server-URL"
  final val X_Pithos_Root_Path  = "X-Pithos-Root-Path"
  final val X_Pithos_UUID       = "X-Pithos-UUID"
  final val X_Pithos_Token      = "X-Pithos-Token"
  final val X_Auth_Token        = "X-Auth-Token"

  val pithosApiCache = CacheBuilder.
    newBuilder().
    maximumSize(50).
    build[ServiceInfo, PithosApi](
      new CacheLoader[ServiceInfo, PithosApi] {
        def load(serviceInfo: ServiceInfo): PithosApi = PithosClientFactory.newClient(serviceInfo)
      }
    )

  def pithos(serviceInfo: ServiceInfo): PithosApi = pithosApiCache.get(serviceInfo)

  def getPithosServerURL(request: Request): String = {
    val headers = request.headerMap

    if(!headers.contains(X_Pithos_Server_URL)) {
      if(!pithosServerURL().isEmpty) {
        headers.add(X_Pithos_Server_URL, pithosServerURL())
      }
    }

    headers.get(X_Pithos_Server_URL).orNull
  }

  def getPithosRootPath(request: Request): String = {
    val headers = request.headerMap

    if(!headers.contains(X_Pithos_Root_Path)) {
      if(!pithosRootPath().isEmpty) {
        headers.add(X_Pithos_Root_Path, pithosRootPath())
      }
    }

    headers.get(X_Pithos_Root_Path).orNull
  }

  def getPithosUUID(request: Request): String = {
    val headers = request.headerMap

    if(!headers.contains(X_Pithos_UUID)) {
      if(!pithosUUID().isEmpty) {
        headers.add(X_Pithos_UUID, pithosUUID())
      }
    }

    headers.get(X_Pithos_UUID).orNull
  }

  def getPithosToken(request: Request): String = {
    val headers = request.headerMap

    if(!headers.contains(X_Pithos_Token)) {
      if(headers.contains(X_Auth_Token)) {
        headers.add(X_Pithos_Token, headers.get(X_Auth_Token).orNull)
      }
    }

    headers.get(X_Pithos_Token).orNull
  }

  def checkPithosToken(request: Request): Boolean = getPithosToken(request) ne null

  def getPithosServiceInfo(request: Request): ServiceInfo = {
    val headers = request.headerMap

    val serverURL = new URL(headers.get(X_Pithos_Server_URL).orNull)
    val rootPath  = headers.get(X_Pithos_Root_Path).orNull
    val uuid = headers.get(X_Pithos_UUID).orNull
    val token = headers.get(X_Pithos_Token).orNull

    ServiceInfo(
      serverURL = serverURL,
      rootPath  = rootPath,
      uuid      = uuid,
      token     = token
    )
  }

  val authFilter = new Filter {
    def authenticate(request: Request): Future[Response] = {
      val response = request.response
      response.status = Status.Unauthorized
      val rh = response.headerMap
      rh.add(HeaderNames.Content_Type,     MediaTypes.Text_Html)
      rh.add(HeaderNames.WWW_Authenticate, s"Keystone uri='${authURL()}'")
      rh.add(HeaderNames.Content_Length,   "0")

      response.future
    }

    override def apply(request: Request, service: Service): Future[Response] = {
      if(isCdmiCapabilitiesUri(request.uri)) {
        return service(request)
      }

      // If we do not have the X-Auth-Token header present, then we need to send the user for authentication
      getPithosToken(request) match {
        case null if authRedirect() ⇒
          log.warning(s"Unauthenticated ${request.method} ${request.uri}")
          authenticate(request)

        case _ ⇒
          service(request)
      }
    }
  }

  final val postTokensJsonFmt = """{ "auth": { "token": { "id": "%s" } } }"""

  val uuidCheck = new Filter {
    // http://www.synnefo.org/docs/synnefo/latest/identity-api-guide.html#tokens-api-operations
    def postTokens(request: Request): Future[Response] = {
      val jsonFmt = postTokensJsonFmt
      val token = getPithosToken(request)
      val jsonPayload = jsonFmt.format(token)

      val httpClient = FinagleClientFactory.newClient(tokensURL())

      val postTokensRequest =
        RequestBuilder().
          url(tokensURL()).
          addHeader(StdHeader.Content_Type.headerName(), StdMediaType.Application_Json.value()).
          buildPost(Buf.ByteArray.Owned(jsonPayload.getBytes(StandardCharsets.UTF_8)))

      httpClient(postTokensRequest)
    }

    override def apply(request: Request, service: Service): Future[Response] = {
      if(isCdmiCapabilitiesUri(request.uri)) {
        return service(request)
      }

      getPithosUUID(request) match {
        case null if getPithosToken(request) ne null ⇒
          postTokens(request).transform {
            case Return(postTokensResponse) if postTokensResponse.statusCode == 200 ⇒
              val jsonTree = Json.jsonStringToTree(postTokensResponse.contentString)

              if(jsonTree.has("access")) {
                val accessTree = jsonTree.get("access")
                if(accessTree.has("token")) {
                  val tokenTree = accessTree.get("token")
                  if(tokenTree.has("tenant")) {
                    val tenantTree = tokenTree.get("tenant")
                    if(tenantTree.has("id")) {
                      val idTree = tenantTree.get("id")
                      if(idTree.isTextual) {
                        val uuid = idTree.asText()
                        request.headerMap.add(X_Pithos_UUID, uuid)
                        log.info(s"Derived $X_Pithos_UUID: $uuid")
                      }
                    }
                  }
                }
              }

              getPithosUUID(request) match {
                case null ⇒
                  // still not found
                  internalServerError(
                    request,
                    new Exception(s"Could not retrieve UUID from ${tokensURL()}"),
                    PithosErrorRef.PIE001
                  )
                case _ ⇒
                  service(request)
              }

            case Return(postTokensResponse) ⇒
              // TODO Check the status we return
              textPlain(request, postTokensResponse.status, postTokensResponse.contentString)

            case Throw(t) ⇒
              log.error(s"Calling ${tokensURL()}")
              internalServerError(request, t, PithosErrorRef.PIE009)
          }

        case uuid if uuid ne null ⇒
          log.info(s"Given $X_Pithos_UUID: $uuid")
          service(request)

        case _ ⇒
          service(request)
      }
    }
  }

  val pithosHeadersFilter = new Filter {
    override def apply(request: Request, service: Service): Future[Response] = {
      // Pithos header check is needed only for URIs that result in calling Pithos
      if(isCdmiCapabilitiesUri(request.uri)) {
        return service(request)
      }

      val errorBuffer = new java.lang.StringBuilder()
      def addError(s: String): Unit = {
        if(errorBuffer.length() > 0) { errorBuffer.append('\n') }
        errorBuffer.append(s)
      }

      val url = getPithosServerURL(request)
      val rootPath = getPithosRootPath(request)
      val uuid = getPithosUUID(request)
      val token = getPithosToken(request)
      if((url eq null) || url.isEmpty) {
        addError(s"No Pithos+ server URL. Please set header $X_Pithos_Server_URL")
      }

      if((rootPath eq null) || rootPath.isEmpty) {
        addError(s"No Pithos+ server root path. Please set header $X_Pithos_Root_Path")
      }

      if((uuid eq null) || uuid.isEmpty) {
        addError(s"No Pithos+ UUID. Please set header $X_Pithos_UUID")
      }

      if((token eq null) || token.isEmpty) {
        addError(s"No Pithos+ user token. Please set header $X_Pithos_Token or $X_Auth_Token")
      }

      if(errorBuffer.length() > 0) {
        badRequest(
          request,
          PithosErrorRef.PBR001,
          errorBuffer
        )
      }
      else {
        service(request)
      }
    }
  }

  val myFilters = Vector(authFilter, uuidCheck, pithosHeadersFilter)
  override def mainFilters = super.mainFilters ++ myFilters

  override def flags: Seq[GlobalFlag[_]] = super.flags ++
    Seq(pithosTimeout, pithosServerURL, pithosRootPath, authURL, authRedirect, tokensURL)

  def fixPathFromContentType(path: String, contentType: String): String =
    contentType match {
      case MediaTypes.Application_Directory | MediaTypes.Application_Folder ⇒
        s"$path/"

      case MediaTypes.Application_CdmiContainer ⇒
        s"$path/"

      case _ if contentType.startsWith(MediaTypes.Application_DirectorySemi) ||
                contentType.startsWith(MediaTypes.Application_FolderSemi) ⇒
        s"$path/"

      case _ ⇒
        path
    }

  def transformResponse[T](
    request: Request,
    resultF: Future[TResult[T]],
    errorRef: IErrorRef,
    onError: (TResult[T]) ⇒ Future[Response],
    onSuccess: (TResult[T]) ⇒ Future[Response]
  ): Future[Response] = {
    resultF.transform {
      case Return(result) if result.isSuccess ⇒
        onSuccess(result)

      case Return(result) ⇒
        onError(result)

      case Throw(t) ⇒
        internalServerError(request, t, errorRef)
    }
  }

  /**
   * We delegate to `DELETE_object_cdmi`.
   *
   * @note The relevant sections from CDMI 1.0.2 are 8.8, 11.5 and 11.7.
   */
  def DELETE_object_or_queue_or_queuevalue_cdmi(request: Request, path: List[String]): Future[StdCdmiPithosServer.Response] = {
    // We support only data objects
    DELETE_object_cdmi(request, path)
  }

  /**
   * Lists the contents of a container.
   */
  override def GET_container_cdmi(
    request: Request, containerPath: List[String]
  ): Future[Response] = {

    val serviceInfo = getPithosServiceInfo(request)
    val folderPath = containerPath mkString "/"

    val checkResponseF = pithos(serviceInfo).checkExistsObject(serviceInfo, folderPath)
    checkResponseF.transform {
      case Return(checkResult) if checkResult.isSuccess ⇒
        val resultData = checkResult.successData.get
        if(resultData.isContainerOrDirectory) {
          val listResponseF = pithos(serviceInfo).listObjectsInPath(serviceInfo, folderPath)
          listResponseF.transform {
            case Return(listResult) if listResult.isSuccess ⇒
              val listObjectsInPath = listResult.successData.get.objects
              val children =
                for {
                  oip ← listObjectsInPath
                } yield {
                  // Pithos returns all the path part after the pithos container.
                  // Note that Pithos container is not the same as CDMI container.
                  log.debug(s"Child: '${oip.container}/${oip.path}' = ${oip.contentType}")
                  val path = oip.path.lastIndexOf('/') match {
                    case -1 ⇒ oip.path
                    case i ⇒ oip.path.substring(i + 1)
                  }

                  fixPathFromContentType(path, oip.contentType)
                }

              val requestPath = request.path
              val parentPath = requestPath.parentPath

              val container = ContainerModel(
                objectID = requestPath,
                objectName = requestPath,
                parentURI = parentPath,
                parentID = parentPath,
                domainURI = "",
                childrenrange = Model.childrenRangeOf(children),
                children = children
              )
              val jsonContainer = Json.objectToJsonString(container)
              okAppCdmiContainer(request, jsonContainer)

            case Return(listResult) ⇒
              textPlain(request, listResult.status)

            case Throw(t) ⇒
              internalServerError(request, t, PithosErrorRef.PIE002)
          }
        }
        else {
          notFound(request)
        }

      case Return(checkResult) ⇒
        textPlain(request, checkResult.status, checkResult.errorDetails.getOrElse(""))

      case Throw(t) ⇒
        internalServerError(request, t, PithosErrorRef.PIE011)
    }
  }

  def PUT_container_(
    request: Request, containerPath: List[String]
  ): Future[Response] = {

    val serviceInfo = getPithosServiceInfo(request)
    val path = containerPath mkString "/"
    // FIXME If the folder does not exist, the result here is just an empty folder
    val responseF = pithos(serviceInfo).createDirectory(serviceInfo, path)
    responseF.transform {
      case Return(result) if result.isSuccess ⇒
        val requestPath = request.uri
        val parentPath = requestPath.parentPath
        val children = Seq()

        val container = ContainerModel(
          objectID = requestPath,
          objectName = requestPath,
          parentURI = parentPath,
          parentID = parentPath,
          domainURI = "",
          childrenrange = Model.childrenRangeOf(children),
          children = children
        )
        val jsonContainer = Json.objectToJsonString(container)
        okAppCdmiContainer(request, jsonContainer)

      case Return(createDirectoryResponse) ⇒
        badRequest(
          request,
          PithosErrorRef.PBR002,
          createDirectoryResponse.errorDetails.getOrElse("")
        )

      case Throw(t) ⇒
        internalServerError(request, t, PithosErrorRef.PIE003)
    }
  }


  /**
   * Creates a container using CDMI content type.
   *
   * @note Section 9.2 of CDMI 1.0.2: Create a Container Object using CDMI Content Type
   */
  override def PUT_container_cdmi_create(
    request: Request, containerPath: List[String]
  ): Future[Response] =
    PUT_container_(request, containerPath)


  /**
   * Creates/updates a container using CDMI content type.
   *
   * @note Section 9.2 of CDMI 1.0.2: Create a Container Object using CDMI Content Type
   * @note Section 9.5 of CDMI 1.0.2: Update a Container Object using CDMI Content Type
   */
  override def PUT_container_cdmi_create_or_update(
    request: Request, containerPath: List[String]
  ): Future[Response] =
    PUT_container_(request, containerPath)
  
  def DELETE_container_(
    request: Request, containerPath: List[String]
  ): Future[Response] = {

    val serviceInfo = getPithosServiceInfo(request)
    val path = containerPath mkString "/"
    val responseF = pithos(serviceInfo).deleteDirectory(serviceInfo, path)
    
    transformResponse[Unit](
      request = request,
      resultF = responseF,
      errorRef  = PithosErrorRef.PIE004,
      onError   = result ⇒ textPlain(request, result.status, result.errorDetails.getOrElse("")),
      onSuccess = result ⇒ okTextPlain(request)
    )
  }

  /**
   * Deletes a container using a CDMI content type.
   *
   * @note Section 9.6 of CDMI 1.0.2: Delete a Container Object using CDMI Content Type
   */
  override def DELETE_container_cdmi(
    request: Request, containerPath: List[String]
  ): Future[Response] = DELETE_container_(request, containerPath)

  /**
   * Deletes a container using a non-CDMI content type.
   *
   * @note Section 9.7 of CDMI 1.0.2: Delete a Container Object using a Non-CDMI Content Type
   */
  override def DELETE_container_noncdmi(
    request: Request, containerPath: List[String]
  ): Future[Response] = DELETE_container_(request, containerPath)

  def GET_object_(
    request: Request,
    objectPath: List[String]
  )(onSuccess: (GetObject2ResultData) ⇒ Future[Response]): Future[Response] = {
    val serviceInfo = getPithosServiceInfo(request)

    val path = objectPath mkString "/"
    val checkResponseF = pithos(serviceInfo).checkExistsObject(serviceInfo, path)

    transformResponse[CheckExistsObjectResultData](
      request = request,
      resultF = checkResponseF,
      errorRef  = PithosErrorRef.PIE012,
      onError   = checkResult ⇒ textPlain(request, checkResult.status, checkResult.errorDetails.getOrElse("")),
      onSuccess = checkResult ⇒ {
        val resultData = checkResult.successData.get

        if(resultData.isContainerOrDirectory) {
          // This is a folder or container, not a file. Go away!
          notFound(request)
        }
        else {
          val objectResponseF = pithos(serviceInfo).getObject2(serviceInfo, path, null)

          transformResponse[GetObject2ResultData](
            request = request,
            resultF = objectResponseF,
            errorRef = PithosErrorRef.PIE005,
            onError = objectResult ⇒ textPlain(request, objectResult.status),
            onSuccess = objectResult ⇒ onSuccess(objectResult.successData.get)
          )
        }
      }
    )
  }


  /**
   * Read a data object using CDMI content type.
   *
   * @note Section 8.4 of CDMI 1.0.2: Read a Data Object using CDMI Content Type
   */
  override def GET_object_cdmi(request: Request, objectPath: List[String]): Future[Response] = {
    GET_object_(request, objectPath) { resultData ⇒
      val contents = resultData.objBuf
      val contentsAsArray = Buf.ByteArray.Owned.extract(contents)
      val size = contents.length
      val contentType = resultData.Content_Type
      val requestPath = request.path
      val requestPathNoObjectIdPrefix = requestPath.removePrefix("/cdmi_objectid")
      val parentPath = requestPathNoObjectIdPrefix.parentPath
      val isTextPlain = contentType.exists(_.startsWith(MediaTypes.Text_Plain))
      val value =
        if(isTextPlain) new String(contentsAsArray, StandardCharsets.UTF_8)
        else            Base64.encodeArray(contentsAsArray)
      val vte = if(isTextPlain) "utf-8" else "base64"

      val model = ObjectModel(
        objectID = requestPathNoObjectIdPrefix,
        objectName = requestPathNoObjectIdPrefix,
        parentURI = parentPath,
        parentID = parentPath,
        domainURI = "",
        mimetype = contentType.getOrElse(""),
        metadata = Map(StorageSystemMetadata.cdmi_size.name() → size.toString),
        valuetransferencoding = vte,
        valuerange = s"0-${size - 1}",
        value = value
      )
      val jsonModel = Json.objectToJsonString(model)

      okAppCdmiObject(request, jsonModel)
    }
  }

  /**
   * Read a data object using non-CDMI content type.
   *
   * @note Section 8.5 of CDMI 1.0.2: Read a Data Object using a Non-CDMI Content Type
   */
  override def GET_object_noncdmi(request: Request, objectPath: List[String]): Future[Response] = {
    GET_object_(request, objectPath) { resultData ⇒
      val status = Status.Ok
      val response = Response(request.version, status)
      response.content = resultData.objBuf
      resultData.Content_Type  .foreach(response.contentType   = _)
      resultData.Content_Length.foreach(response.contentLength = _)
      response.headerMap.add(HeaderNames.X_CDMI_Specification_Version, currentCdmiVersion)

      end(request, response).future
    }
  }


  /**
   * Create a data object in a container using CDMI content type.
   */
  override def PUT_object_cdmi_create_or_update(
    request: Request, objectPath: List[String]
  ): Future[Response] = {

    val serviceInfo = getPithosServiceInfo(request)
    val path = objectPath mkString "/"

    val content = request.contentString
    val jsonTree =
      try Json.jsonStringToTree(content)
      catch {
        case e: com.fasterxml.jackson.core.JsonParseException ⇒
          log.error(e.toString)
          return badRequest(
            request,
            PithosErrorRef.PBR008,
            s"Could not parse input as JSON.\n${e.getMessage}"
          )
      }

    val mimeTypeNode = jsonTree.get("mimetype")
    val valueNode = jsonTree.get("value")
    val vteNode = jsonTree.get("valuetransferencoding")

    if((mimeTypeNode ne null) && !mimeTypeNode.isTextual) {
      return badRequest(
        request,
        PithosErrorRef.PBR003,
        s"Incorrect type ${mimeTypeNode.getNodeType} of 'mimetype' field. Should be ${JsonNodeType.STRING}"
      )
    }

    if((vteNode ne null) && !vteNode.isTextual) {
      return badRequest(
        request,
        PithosErrorRef.PBR004,
        s"Incorrect type ${vteNode.getNodeType} of 'valuetransferencoding' field. Should be ${JsonNodeType.STRING}"
      )
    }

    // Not mandated by the spec but we currently support only the presence of "value"
    if(valueNode eq null) {
      return badRequest(
        request,
        PithosErrorRef.PBR005,
        "'value' is not present"
      )
    }
    if(!valueNode.isTextual) {
      return badRequest(
        request,
        PithosErrorRef.PBR006,
        s"Incorrect type ${valueNode.getNodeType} of 'value' field. Should be ${JsonNodeType.STRING}"
      )
    }

    val mimetype = mimeTypeNode match {
      case null ⇒ MediaTypes.Text_Plain
      case _    ⇒ mimeTypeNode.asText()
    }

    val vte = vteNode match {
      case null ⇒
        "utf-8"

      case node ⇒
        node.asText().toLowerCase(Locale.US) match {
          case text @ ("utf-8" | "base64") ⇒
            text

          case text ⇒
            return badRequest(
              request,
              PithosErrorRef.PBR007,
              s"Incorrect value of 'valuetransferencoding' field [$text]"
            )
        }
    }

    val bytes = valueNode.asText() match {
      case null ⇒
        Array[Byte]()

      case utf8   if vte == "utf-8" ⇒
        utf8.getBytes(vte)

      case base64 if vte == "base64" ⇒
        Base64.decodeString(base64)
    }

    val putObjectResponseF = pithos(serviceInfo).putObject(serviceInfo, path, bytes, mimetype)
    transformResponse[Unit](
      request = request,
      resultF = putObjectResponseF,
      errorRef = PithosErrorRef.PIE006,
      onError  = result ⇒ textPlain(request, result.status, result.errorDetails.getOrElse("")),
      onSuccess = result ⇒ {
        val size = bytes.length
        val requestPath = request.path
        val requestPathNoObjectIdPrefix = requestPath.removePrefix("/cdmi_objectid")
        val parentPath = requestPathNoObjectIdPrefix.parentPath
        val valueRangeEnd = if(size == 0) 0 else size - 1

        val model = ObjectModel(
          objectID = requestPath,
          objectName = requestPath,
          parentURI = parentPath,
          parentID = parentPath,
          domainURI = "",
          mimetype = mimetype,
          metadata = Map(StorageSystemMetadata.cdmi_size.name() → size.toString),
          valuetransferencoding = vte,
          valuerange = s"0-$valueRangeEnd",
          value = "" // TODO technically should not be present
        )

        val jsonModel = Json.objectToJsonString(model)
        okJson(request, jsonModel)
      }
    )
  }


  /**
   * Creates a data object in a container using CDMI content type.
   *
   * @note Section 8.2 of CDMI 1.0.2: Create a Data Object Using CDMI Content Type
   */
  override def PUT_object_cdmi_create(request: Request, objectPath: List[String]): Future[Response] =
    PUT_object_cdmi_create_or_update(request, objectPath)

  /**
   * Create a data object in a container using non-CDMI content type.
   * The given `contentType` is guaranteed to be not null.
   */
  override def PUT_object_noncdmi(
    request: Request, objectPath: List[String], contentType: String
  ): Future[Response] = {

    val serviceInfo = getPithosServiceInfo(request)
    val path = objectPath.mkString("/")

    val payload = request.content
    val responseF = pithos(serviceInfo).putObject(serviceInfo, path, payload, contentType)
    transformResponse[Unit](
      request   = request,
      resultF   = responseF,
      errorRef  = PithosErrorRef.PIE007,
      onError   = result ⇒ textPlain(request, result.status, result.errorDetails.getOrElse("")),
      onSuccess = result ⇒ okTextPlain(request)
    )
  }

  /**
   * Delete a data object (file).
   */
  def DELETE_object_(request: Request, objectPath: List[String]): Future[Response] = {
    val serviceInfo = getPithosServiceInfo(request)
    val path = objectPath.mkString("/")

    val responseF = pithos(serviceInfo).deleteFile(serviceInfo, path)
    transformResponse[Unit](
      request   = request,
      resultF   = responseF,
      errorRef  = PithosErrorRef.PIE008,
      onError   = result ⇒ textPlain(request, result.status, result.errorDetails.getOrElse("")),
      onSuccess = result ⇒ okTextPlain(request)
    )
  }

  /**
   * Deletes a data object in a container using CDMI content type.
   *
   * @note Section 8.8 of CDMI 1.0.2: Delete a Data Object using CDMI Content Type
   */
  override def DELETE_object_cdmi(request: Request, objectPath: List[String]): Future[Response] =
    DELETE_object_(request, objectPath)


  /**
   * Deletes a data object in a container using non-CDMI content type.
   *
   * @note Section 8.9 of CDMI 1.0.2: Delete a Data Object using a Non-CDMI Content Type
   */
  override def DELETE_object_noncdmi(request: Request, objectPath: List[String]): Future[Response] =
    DELETE_object_(request, objectPath)
}
