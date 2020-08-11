package ctx;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpListener;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IRequestInfo;
import burp.IResponseInfo;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.HashMap;

public class OpenBankingExtensionHttpListener implements IHttpListener {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private PrintWriter stdout;
    private OpenBankingExtensionTabController tabCtr;

    public OpenBankingExtensionHttpListener(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers, PrintWriter stdout,
                                            OpenBankingExtensionTabController tabCtr) {
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.stdout = stdout;
        this.tabCtr = tabCtr;
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        IHttpService httpService = messageInfo.getHttpService();

        // OAuth Listener
        String cbUrl = tabCtr.getGui().getTabGeneral().getTextRedirect().getText();
        if(!messageIsRequest && !cbUrl.isEmpty()) {
            oAuthListener(messageInfo, cbUrl);
        }

        // Message Signing
        messageSigning(messageIsRequest, messageInfo);
    }

    // OAuth listener functions
    /**
     * This function is used to wait for the OAuth return code after the end user has authorised the action.
     * We are actually waiting for a redirect response and are looking at the location header. If the
     * location header matches the TPP redirect URL and contains the OAuth code, then we grab the code and send a new
     * request to generate the next bearer token. This needs to be done automatically as the return code from the ASPSP
     * is only valid for a few short seconds.
     *
     * @param messageInfo burp request/response
     * @param cbUrl the TPP redirect URL we are listening for
     */
    private void oAuthListener(IHttpRequestResponse messageInfo, String cbUrl) {
        byte[] responseData = messageInfo.getResponse();
        IResponseInfo responseInfo = helpers.analyzeResponse(responseData);

        String locationHeader = getLocationHeader((ArrayList<String>) responseInfo.getHeaders(), cbUrl);

        // only continue if the response contains the location header we are looking for
        if (!locationHeader.isEmpty()) {
            String code = retrieveCodeFromHeader(locationHeader);
            tabCtr.getGui().getTabAuthToken().getTxtCode().setText(code);

            if (code.isEmpty()) {
                tabCtr.getGui().getTabAuthToken().getOutput().setText(
                        tabCtr.getGui().getTabAuthToken().getOutput().getText() + "\n\nERROR: Could not extract code from location header\n\n");
            } else {
                // mandatory parameters to be able to send out the request for the next bearer token
                String redirectUri = tabCtr.getGui().getTabGeneral().getTextRedirect().getText();
                String clientId = tabCtr.getGui().getTabGeneral().getTextClientId().getText();
                String oAuthUrl = tabCtr.getGui().getTabGeneral().getTextOAuth().getText();
                String scope = tabCtr.getGui().getTabGeneral().getTextScope().getText();

                if (redirectUri.isEmpty() || clientId.isEmpty() || oAuthUrl.isEmpty() || scope.isEmpty()) {
                    tabCtr.getGui().getTabAuthToken().getOutput().setText(
                            tabCtr.getGui().getTabAuthToken().getOutput().getText() +
                                    "\n\nERROR: Please provide the mandatory parameters for the OAuth request in the settings tab.\n\n");
                } else {
                    HashMap<String,String> hostDetails = retrieveHostAndPath(oAuthUrl);
                    byte[] callbackRequest = buildCallbackRequest(scope, redirectUri, clientId, code, hostDetails);

                    tabCtr.getGui().getTabAuthToken().getOutput().setText(
                            tabCtr.getGui().getTabAuthToken().getOutput().getText() + "\n*** REQUEST *** \n" + new String(callbackRequest) + "\n");

                    int port = 443;
                    boolean useHttp = true;
                    if (oAuthUrl.contains("http://")) {
                        port = 80;
                        useHttp = false;
                    }

                    byte[] callbackResponse = callbacks.makeHttpRequest(hostDetails.get("host"), port, useHttp, callbackRequest);
                    if (callbackResponse != null) {
                        String oAuthResponse = new String(callbackResponse);
                        tabCtr.getGui().getTabAuthToken().getOutput().setText(tabCtr.getGui().getTabAuthToken().getOutput().getText() +
                                "\n*** RESPONSE *** \n" + oAuthResponse + "\n\n");
                        setBearerTokenTextField(oAuthResponse);
                    }
                }
            }
        }
    }

    /**
     * Extracts the bearer token from the OAuth response and sets the value in the Auth Token tab in the Current Token
     * field.
     *
     * @param oAuthResponse oAuth response
     */
    private void setBearerTokenTextField(String oAuthResponse) {
        //headers + body
        // body example {"access_token":"exampleBearerToken","refresh_token":"exampleRefreshToken","token_type":"Bearer","expires_in":299}
        // body = get index of first { to the rest of the string
        int bodyStartIndex = oAuthResponse.indexOf("{");
        if(bodyStartIndex != -1) {
            String body = oAuthResponse.substring(bodyStartIndex);
            JsonParser jsonParser = new JsonParser();
            JsonObject jsonBody = (JsonObject)jsonParser.parse(body);
            tabCtr.getGui().getTabAuthToken().getTxtBearerToken().setText(jsonBody.get("access_token").getAsString());
        }
    }

    /**
     * From the provided OAuth URL extract the host and the path for the burp request
     *
     * @param oAuthUrl - i.e. https://aspsp.com/as/token.oauth2
     * @return host = aspsp.com - path = /as/token.oauth2
     */
    private HashMap<String,String> retrieveHostAndPath(String oAuthUrl) {
        HashMap<String,String> details = new HashMap<String,String>();

        String[] splitUrl = oAuthUrl.replace("https://", "").replace("http://", "").split("/");
        String extractedHost = splitUrl[0];
        String extractedPath = "";
        for (int j = 1; j < splitUrl.length; j++) {
            extractedPath += splitUrl[j];
            if (j < splitUrl.length - 1) {
                extractedPath += "/";
            }
        }

        details.put("host", extractedHost);
        details.put("path", extractedPath);
        return details;
    }

    /**
     * This function builds the OAuth request for the second bearer token.
     *
     * @param scope - Open Banking scope: openid [accounts|payments|fundsconfirmation]
     * @param redirectUri - TPP redirect URI
     * @param clientId - TPP client ID
     * @param code - current auth code returned by the ASPSP
     * @param hostDetails - OAuth host and path, i.e. host = aspsp.com - path = /as/token.oauth2
     * @return burp request
     */
    private byte[] buildCallbackRequest(String scope, String redirectUri, String clientId, String code, HashMap<String,String> hostDetails) {
        // REQUEST BODY
        //   grant_type=authorization_code&redirect_uri=https://tpp.com/callback&client_id=<dc-clientID>&code=<code>
        String callbackRequestBody = "grant_type=authorization_code&scope={0}&redirect_uri={1}&client_id={2}&code={3}";
        callbackRequestBody = callbackRequestBody.replace("{0}", scope.replace(" ", "+"))
                .replace("{1}", redirectUri)
                .replace("{2}", clientId)
                .replace("{3}", code);

        // REQUEST HEADER
        ArrayList<String> callbackHeaders = new ArrayList<String>();
        callbackHeaders.add("POST /" + hostDetails.get("path") + " HTTP/1.1");
        callbackHeaders.add("Host: " + hostDetails.get("host"));
        callbackHeaders.add("Accept: application/json");
        callbackHeaders.add("Content-Type: application/x-www-form-urlencoded");
        callbackHeaders.add("Connection: close");
        callbackHeaders.add("Content-Length: " + callbackRequestBody.length());

        return helpers.buildHttpMessage(callbackHeaders, callbackRequestBody.getBytes());
    }

    /**
     * function extracts the code parameter from the Location header
     *
     * @param locationHeader for example "Location: https://tpp.com/callback#code=<code>&id_token=<jwt>&state=<state>"
     * @return code
     */
    private String retrieveCodeFromHeader(String locationHeader) {
        // Location: https://tpp.com/callback#code=<code>&id_token=<jwt>&state=<state>
        String extractedParams = locationHeader.substring(locationHeader.indexOf("#"));
        String[] locationParams = extractedParams.split("&");
        String code = "";
        for (int n = 0; n < locationParams.length; n++) {
            if (locationParams[n].contains("code")) {
                code = locationParams[n].replace("code=", "").replace("#", "");
            }
        }
        return code;
    }

    /**
     * inspects the headers of the current response. If the location header with the url we are looking for is
     * identified, it will return the full location header as a String.
     *
     * @return locationHeader
     */
    private String getLocationHeader(ArrayList<String> responseHeaders, String cbUrl) {
        String locationHeader = "";
        for (int k = 0; k < responseHeaders.size(); k++) {
            if (responseHeaders.get(k).contains("Location:") && responseHeaders.get(k).contains(cbUrl)) {
                locationHeader = responseHeaders.get(k);
                break;
            }
        }
        return locationHeader;
    }


    // Message Signing functions
    /**
     * Sign requests payloads for specified endpoints
     *
     * @param messageIsRequest boolean - is it a request or response
     * @param messageInfo request/response details
     */
    private void messageSigning(boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        IHttpService httpService = messageInfo.getHttpService();
        ArrayList<String> urls = getMessageSigningEndpoints();

        // first check if message signing of same domain specified as httpService only gives the host
        // don't want to analyse all requests coming in - just the ones that match the message signing endpoints
        // the check if the path matches the current request will be further down
        if (messageIsRequest && !urls.isEmpty() && isMessageSigningEndpointDomain(httpService.getHost(), urls)) {

            byte[] requestData = messageInfo.getRequest();
            IRequestInfo requestInfo = helpers.analyzeRequest(httpService, requestData);

            if(isMessageSigningEndpoint(requestInfo.getUrl().toString(), urls)) {
                OpenBankingMessageSigning ctxMessageSigning = new OpenBankingMessageSigning();
                String alg = this.tabCtr.getGui().getTabGeneral().getTextAlg().getText();
                String kid = this.tabCtr.getGui().getTabGeneral().getTextKid().getText();
                String iss = this.tabCtr.getGui().getTabGeneral().getTextIss().getText();
                String tan = this.tabCtr.getGui().getTabGeneral().getTextTan().getText();
                String crit = this.tabCtr.getGui().getTabGeneral().getTextCrit().getText();
                String privateKey = this.tabCtr.getGui().getTabGeneral().getTextPrivateKey().getText();
                String typ = this.tabCtr.getGui().getTabGeneral().getTextTyp().getText();
                String cty = this.tabCtr.getGui().getTabGeneral().getTextCty().getText();
                String[] critValues = crit.split(",");

                if (!alg.trim().isEmpty() && !kid.trim().isEmpty() && !iss.trim().isEmpty() &&
                        !tan.trim().isEmpty() && !crit.trim().isEmpty() && !privateKey.trim().isEmpty()) {

                    String request = new String(messageInfo.getRequest());
                    String requestBody = request.substring(requestInfo.getBodyOffset());
                    String detachedJws = ctxMessageSigning.generateDetachedJWS(requestBody, alg, privateKey, kid,
                            iss, tan, critValues, typ, cty);

                    ArrayList<String> headers = (ArrayList<String>) requestInfo.getHeaders();
                    headers.add("x-jws-signature: " + detachedJws);

                    byte[] newMessage = helpers.buildHttpMessage(headers, requestBody.getBytes());
                    messageInfo.setRequest(newMessage);

                    //verify signature if public key has been provided
                    //currently only shown if signature is invalid in the Extender - Open Banking - Output
                    String publicKey = this.tabCtr.getGui().getTabGeneral().getTextPublicKey().getText();
                    if(!publicKey.isEmpty()) {
                        boolean isValid = ctxMessageSigning.verifySigning(detachedJws, alg, requestBody, publicKey, critValues);
                        if(!isValid) {
                            stdout.println("WARNING - invalid signature for: " + requestBody);
                        }
                    }
                } else {
                    stdout.println("WARNING - can not sign payload due to missing parameters. Please double check your settings.");
                }
            }
        }
    }

    /**
     * Check whether the url of the current request matches the endpoints specified.
     *
     * @param url of the current request
     * @param endpoints where message signing is enabled
     * @return true if current request needs to be signed.
     */
    private boolean isMessageSigningEndpoint(String url, ArrayList<String> endpoints) {
        //url example: http://ob.local:80/pisp
        //domain was already checked - now needs to be the correct path
        String urlWithoutScheme = url.replace("http://", "").replace("https://", "");
        String currentPath = urlWithoutScheme.substring(urlWithoutScheme.indexOf("/"));

        boolean signEndpoint = false;
        for(String endpoint: endpoints) {
            String endpointWithoutScheme = endpoint.replace("http://", "").replace("https://", "");
            String endpointPath = endpointWithoutScheme.substring(endpointWithoutScheme.indexOf("/"));

            //needs to match the full path
            //needs to be refined to specific HTTP methods (POST, GET etc.) if necessary
            if(currentPath.equalsIgnoreCase(endpointPath)) {
                signEndpoint = true;
                break;
            }
        }
        return signEndpoint;
    }

    /**
     * Before analysing the request it is only possible to view the domain/host of the current request. So as not to analyse
     * each incoming request right away we first check if the domain is the one we are looking for.
     * Note: it might not be much difference analysing each request directly, therefore feel free to edit the code.
     *
     * @param host is the domain of the current request
     * @param endpoints where message signing is enabled
     * @return true if current request needs to be signed.
     */
    private boolean isMessageSigningEndpointDomain(String host, ArrayList<String> endpoints) {
        boolean isSameDomain = false;
        for(String endpoint : endpoints) {
            if(endpoint.contains(host)) {
                isSameDomain = true;
                break;
            }
        }
        return isSameDomain;
    }

    /**
     * Parses user input, which is a comma separated list of urls into an arraylist
     *
     * @return ArrayList<String> of endpoints that need to be signed
     */
    private ArrayList<String> getMessageSigningEndpoints() {
        String messageSigningUrls = this.tabCtr.getGui().getTabGeneral().getTextUrl().getText();
        ArrayList<String> endpoints = new ArrayList<>();

        String[] urlList = messageSigningUrls.split(",");
        for(int i = 0; i < urlList.length; i++) {
            // for the future, probably good idea to do some input validation if the URL is correct format
            endpoints.add(urlList[i].trim());
        }
        return endpoints;
    }
}
