/*
/* Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2016 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.extension.frontEndScanner;

import java.util.Locale;

import org.apache.log4j.Logger;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.zaproxy.zap.extension.alert.ExtensionAlert;
import org.zaproxy.zap.extension.api.API;
import org.zaproxy.zap.extension.api.ApiAction;
import org.zaproxy.zap.extension.api.ApiException;
import org.zaproxy.zap.extension.api.ApiImplementor;
import org.zaproxy.zap.extension.api.ApiResponse;
import org.zaproxy.zap.extension.api.ApiResponseElement;

import net.sf.json.JSONException;
import net.sf.json.JSONObject;

public class FrontEndScannerAPI extends ApiImplementor {
    // TODO shouldnt allow unsafe-inline styles - need to work out where they are being used
    protected static final String CSP_POLICY =
        "default-src 'none'; script-src 'self'; connect-src https://zap wss://zap; frame-src 'self'; img-src 'self' data:; "
        + "font-src 'self' data:; style-src 'self' 'unsafe-inline' ;";

    private static final String PREFIX = "frontEndScanner";

    private ExtensionFrontEndScanner extension;

    private static final String ACTION_GET_SCRIPTS = "getScripts";

    private static final Logger LOGGER = Logger.getLogger(FrontEndScannerAPI.class);

    public FrontEndScannerAPI(ExtensionFrontEndScanner extension) {
        this.extension = extension;
        this.addApiAction(new ApiAction(ACTION_GET_SCRIPTS));
    }

    @Override
    public String getPrefix() {
        return PREFIX;
    }

    @Override
    public String handleCallBack(HttpMessage msg) throws ApiException {
        JSONObject alertParams = JSONObject.fromObject(
          msg.getRequestBody().toString()
        ).getJSONObject("alert");

        try {
            int clientSidePassiveScriptPluginId = 50005;

            HistoryReference historyReference = new HistoryReference(
                alertParams.getInt("historyReferenceId"),
                false
            );

            Alert alert = new Alert(
                clientSidePassiveScriptPluginId,
                alertParams.getInt("risk"),
                alertParams.getInt("confidence"),
                alertParams.getString("name")
            );
            alert.setSource(Alert.Source.PASSIVE);
            alert.setDescription(alertParams.getString("description"));
            // alert.setHistoryRef(historyReference);

            ExtensionAlert extAlert = Control
              .getSingleton()
              .getExtensionLoader()
              .getExtension(ExtensionAlert.class);

            extAlert.alertFound(alert, historyReference);

            return "";
        } catch (JSONException e) {
            LOGGER.debug(e.getMessage());
            // TODO: deserialization failed
            throw new ApiException (ApiException.Type.URL_NOT_FOUND, msg.getRequestHeader().getURI().toString());
        } catch (Exception e) {
            LOGGER.debug(e.getMessage());
            throw new ApiException (ApiException.Type.URL_NOT_FOUND, msg.getRequestHeader().getURI().toString());
        }
        // throw new ApiException (ApiException.Type.URL_NOT_FOUND, msg.getRequestHeader().getURI().toString());
    }

    @Override
    public ApiResponse handleApiAction(String name, JSONObject params) throws ApiException {
        switch (name) {
            case ACTION_GET_SCRIPTS:
                LOGGER.debug("getScripts called");
                break;

            default:
                throw new ApiException(ApiException.Type.BAD_ACTION);
        }

        return ApiResponseElement.OK;
    }
}
