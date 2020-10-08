package com.cdc.apihub.signer.manager.client;

public class Configuration {
    private static ApiClient defaultApiClient = new ApiClient();

    
    public static ApiClient getDefaultApiClient() {
        return defaultApiClient;
    }

    
    public static void setDefaultApiClient(ApiClient apiClient) {
        defaultApiClient = apiClient;
    }
}
