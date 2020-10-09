package com.cdc.apihub.signer.manager.test;

import com.cdc.apihub.signer.manager.client.ApiClient;
import com.cdc.apihub.signer.manager.client.ApiException;
import com.cdc.apihub.signer.manager.client.ApiResponse;
import com.cdc.apihub.signer.manager.client.api.SecurityApi;
import com.cdc.apihub.signer.manager.interceptor.SignerInterceptor;

import okhttp3.OkHttpClient;

import java.util.concurrent.TimeUnit;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ApiTest {
	
	private String keystoreFile = "your_path_for_your_keystore/keystore.jks";
	private String cdcCertFile = "your_path_for_certificate_of_cdc/cdc_cert.pem";
	private String keystorePassword = "your_super_secure_keystore_password";
	private String keyAlias = "your_key_alias";
	private String keyPassword = "your_super_secure_password";
	private String url = "the_url";
	private String xApiKey = "X_Api_Key";
	
	private SignerInterceptor interceptor;

	private Logger logger = LoggerFactory.getLogger(ApiTest.class.getName());
	private final SecurityApi api = new SecurityApi();
	private ApiClient apiClient = null;

	@Before()
	public void setUp() {
		this.interceptor = new SignerInterceptor(keystoreFile, cdcCertFile, keystorePassword, keyAlias, keyPassword);
		this.apiClient = api.getApiClient();
		this.apiClient.setBasePath(url);
		OkHttpClient okHttpClient = new OkHttpClient().newBuilder().readTimeout(30, TimeUnit.SECONDS)
				.addInterceptor(interceptor).build();
		apiClient.setHttpClient(okHttpClient);
	}

	@Test
	public void signerManagerTest() throws ApiException {
		String body = "Esto es un mensaje de prueba";
		
		Integer estatusOK = 200;
		Integer estatusNoContent = 204;
		
		try {

			ApiResponse<?> response = api.securityGenericTest(xApiKey, body);

			Assert.assertTrue(estatusOK.equals(response.getStatusCode()));

			if (estatusOK.equals(response.getStatusCode())) {
				String responseOK = (String) response.getData();
				logger.info(responseOK.toString());
			}

		} catch (ApiException e) {
			
			if (!estatusNoContent.equals(e.getCode())) {
				logger.info("Response received from API: "+interceptor.getErrores().toString());
				logger.info("Response processed by client:"+ e.getResponseBody());
			} else {
				logger.info("The response was a status 204 (NO CONTENT)");
			}
			
			Assert.assertTrue(estatusOK.equals(e.getCode()));
		}
	}

}
