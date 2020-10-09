package com.cdc.apihub.signer.manager.interceptor;

import java.io.IOException;
import java.util.List;

import org.apache.commons.httpclient.HttpStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.gson.Gson;

import com.cdc.apihub.signer.manager.model.Error;
import com.cdc.apihub.signer.manager.model.Errores;
import okhttp3.Interceptor;
import okhttp3.MediaType;
import okhttp3.Protocol;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.Response.Builder;
import okhttp3.ResponseBody;
import okio.Buffer;

public class SignerInterceptor implements Interceptor {
	private Logger logger = LoggerFactory.getLogger(SignerInterceptor.class.getName());
	private Signer signer;
	private Request newRequest;
	private Errores errores = null;
	
	private String keystoreFile;
	private String cdcCertFile;
	private String keystorePassword;
	private String keyAlias;
	private String keyPassword;
	private Boolean parameters;
	
	public SignerInterceptor(String keystoreFile, String cdcCertFile, String keystorePassword, String keyAlias, String keyPassword) {
		this.keystoreFile = keystoreFile;
		this.cdcCertFile = cdcCertFile;
		this.keystorePassword = keystorePassword;
		this.keyAlias = keyAlias;
		this.keyPassword= keyPassword;
		this.parameters = true;
	}
	public SignerInterceptor() {
		this.parameters = false;
	}

	@Override
	public Response intercept(Chain chain) throws IOException {
		this.signer = (this.parameters) ? Signer.getInstance(keystoreFile, cdcCertFile, keystorePassword, keyAlias, keyPassword) : Signer.getInstance();
		Request originalRequest = chain.request();
		this.newRequest = this.procesarFirmado(originalRequest);
		Response response = chain.proceed(newRequest);
		return this.procesarVerificado(response);
	}
	private static String bodyToString(final Request request) {
		try {
			final Request copy = request.newBuilder().build();
			final Buffer buffer = new Buffer();
			copy.body().writeTo(buffer);
			return buffer.readUtf8();
		} catch (final IOException e) {
			return null;
		}
	}
	private Request procesarFirmado(Request originalRequest) {
		logger.debug("Generating signed ...");
		String payload = null;
		List<String> pathSegments = originalRequest.url().encodedPathSegments();

		if (originalRequest.method() == "GET") {
			payload = pathSegments.get(2);
		} else {
			payload = bodyToString(originalRequest);
		}

		String signature = this.signer.signPayload(payload);
		if (signature == null) {
			logger.error("Could not sign the payload");
		} else {
			logger.debug("Signature: " + signature);
		}
		return originalRequest.newBuilder().header("x-signature", signature)
				.method(originalRequest.method(), originalRequest.body()).build();
	}	
	private Response procesarVerificado(Response response) {
		logger.debug("Verifying signed ...");
		ResponseBody bodyAsStream = null;
		Response outResponse = null;
		MediaType contentType = null;
		String signature = null;
		String payload = null;
		byte[] content = null;
		try {
			contentType = response.body().contentType();
			content = response.body().bytes();
			bodyAsStream = ResponseBody.create(contentType, content);
			payload = bodyAsStream.string();
			if(response != null && response.code() != 200) {
				setErrores(payload);
			}			
			logger.debug("Payload received: "+ (String) payload.replaceAll("(\n|\r)", ""));
			List<String> values = response.headers().values("x-signature");
			signature = values.get(0);
			logger.debug("Signature received: "+ signature);
		} catch (IndexOutOfBoundsException e) {
			logger.error("The signature cannot be recovered.");
		} catch (IOException e) {
			logger.error("Unexpected error.");
		} finally {
			if (bodyAsStream != null) {
				bodyAsStream.close();
			}
		}
		if (response.code() == 200) {
			if (this.signer.verifyPayload(payload, signature)) {
				logger.debug("Successful verification.");
				outResponse = buildResponseBody(response.code(), null, response, contentType, content);
			} else {
				logger.error("Signature cannot be verified.");
				outResponse = buildResponseBody(403, "Signature cannot be verified.", response, contentType, null);
			}
		} else if (signature == null) {
			outResponse = buildResponseBody(500, "Signature not received.", response, contentType, null);
		} else {
			outResponse = buildResponseBody(response.code(), null, response, contentType, content);
		}
		return outResponse;
	}
	
	private void setErrores(String payload) {
		logger.debug("Mapped response error from API.");
		Gson gson = new Gson();
		this.errores = gson.fromJson(payload, Errores.class);	
	}
	
	public Errores getErrores() {
		return this.errores;
	}

	private String generateError(String code, String message) {
		logger.debug("Mapped response error from client.");
		Errores errs = new Errores();
		Error err = new Error();
		err.setCodigo(code);
		err.setMensaje(message);
		errs.addErroresItem(err);
		Gson gson = new Gson();
		return gson.toJson(errs);
	}

	private Response buildResponseBody(Integer statusCode, String message, Response response, MediaType contentType,
			byte[] content) {
		ResponseBody responseBody = null;
		String responseMessage = HttpStatus.getStatusText(statusCode);
		if (message != null)
			responseBody = ResponseBody.create(contentType, generateError(String.valueOf(statusCode), message));
		else
			responseBody = ResponseBody.create(contentType, content);
		Response newResponse = new Builder().code(statusCode).protocol(Protocol.HTTP_1_1).message(responseMessage)
				.request(this.newRequest).body(responseBody).headers(response.headers()).build();
		return newResponse;
	}
}
