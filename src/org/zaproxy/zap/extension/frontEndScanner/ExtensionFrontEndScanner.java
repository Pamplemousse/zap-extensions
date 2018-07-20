/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.extension.frontEndScanner;

import java.awt.CardLayout;
import java.awt.Font;
import java.lang.Exception;
import java.lang.String;
import java.io.File;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;
import java.util.UUID;

import javax.swing.ImageIcon;
import javax.swing.JTextPane;

import net.htmlparser.jericho.Element;
import net.htmlparser.jericho.OutputDocument;
import net.htmlparser.jericho.Source;

import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.proxy.ProxyListener;
import org.parosproxy.paros.extension.AbstractPanel;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.utils.FontUtils;
import org.zaproxy.zap.view.ZapMenuItem;


/**
 * An example ZAP extension which adds a top level menu item, a pop up menu item and a status panel.
 * <p>
 * {@link ExtensionAdaptor} classes are the main entry point for adding/loading functionalities provided by the add-ons.
 *
 * @see #hook(ExtensionHook)
 */
public class ExtensionFrontEndScanner extends ExtensionAdaptor implements ProxyListener {

    // The name is public so that other extensions can access it
    public static final String NAME = "ExtensionFrontEndScanner";

    // The i18n prefix, by default the package name - defined in one place to make it easier
    // to copy and change this example
    protected static final String PREFIX = "frontEndScanner";

    private static final String RESOURCE = "/org/zaproxy/zap/extension/frontEndScanner/resources";
    private static final String FRONT_END_SCANNER = Constant.getZapHome() + "/frontEndScanner/front-end-scanner.js";
    private static final String SCRIPTS_FOLDER = Constant.getZapHome() + "/scripts/scripts/front-end/";

    private static final ImageIcon ICON = new ImageIcon(
            ExtensionFrontEndScanner.class.getResource( RESOURCE + "/cake.png"));

    private static final String EXAMPLE_FILE = "example/ExampleFile.txt";

    private ZapMenuItem menuExample;
    private RightClickMsgMenu popupMsgMenuExample;
    private AbstractPanel statusPanel;

    private FrontEndScannerAPI api = new FrontEndScannerAPI(this);

    private static final Logger LOGGER = Logger.getLogger(ExtensionFrontEndScanner.class);

    public ExtensionFrontEndScanner() {
        super(NAME);
    }

    private boolean frontEndScannerEnabled = true;

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        extensionHook.addApiImplementor(this.api);
        extensionHook.addProxyListener(this);

        if (getView() != null) {
            // Register our top menu item, as long as we're not running as a daemon
            // Use one of the other methods to add to a different menu list
            extensionHook.getHookMenu().addToolsMenuItem(getMenuExample());
            // Register our popup menu item
            extensionHook.getHookMenu().addPopupMenuItem(getPopupMsgMenuExample());
            // Register a
            extensionHook.getHookView().addStatusPanel(getStatusPanel());
        }
    }

    @Override
    public boolean canUnload() {
        // The extension can be dynamically unloaded, all resources used/added can be freed/removed from core.
        return true;
    }

    @Override
    public void unload() {
        super.unload();

        // In this example it's not necessary to override the method, as there's nothing to unload
        // manually, the components added through the class ExtensionHook (in hook(ExtensionHook))
        // are automatically removed by the base unload() method.
        // If you use/add other components through other methods you might need to free/remove them
        // here (if the extension declares that can be unloaded, see above method).
    }

    private AbstractPanel getStatusPanel() {
        if (statusPanel == null) {
            statusPanel = new AbstractPanel();
            statusPanel.setLayout(new CardLayout());
            statusPanel.setName(Constant.messages.getString(PREFIX + ".panel.title"));
            statusPanel.setIcon(ICON);
            JTextPane pane = new JTextPane();
            pane.setEditable(false);
            // Obtain (and set) a font with the size defined in the options
            pane.setFont(FontUtils.getFont("Dialog", Font.PLAIN));
            pane.setContentType("text/html");
            pane.setText(Constant.messages.getString(PREFIX + ".panel.msg"));
            statusPanel.add(pane);
        }
        return statusPanel;
    }

    private ZapMenuItem getMenuExample() {
        if (menuExample == null) {
            menuExample = new ZapMenuItem(PREFIX + ".topmenu.tools.title");

            menuExample.addActionListener(new java.awt.event.ActionListener() {
                @Override
                public void actionPerformed(java.awt.event.ActionEvent ae) {
                    // This is where you do what you want to do.
                    // In this case we'll just show a popup message.
                    View.getSingleton().showMessageDialog(
                            Constant.messages.getString(PREFIX + ".topmenu.tools.msg"));
                    // And display a file included with the add-on in the Output tab
                    displayFile(EXAMPLE_FILE);
                }
            });
        }
        return menuExample;
    }

    private void displayFile (String file) {
        if (! View.isInitialised()) {
            // Running in daemon mode, shouldnt have been called
            return;
        }
        try {
            File f = new File(Constant.getZapHome(), file);
            if (! f.exists()) {
                // This is something the user should know, so show a warning dialog
                View.getSingleton().showWarningDialog(
                        Constant.messages.getString(ExtensionFrontEndScanner.PREFIX + ".error.nofile", f.getAbsolutePath()));
                return;
            }
            // Quick way to read a small text file
            String contents = new String(Files.readAllBytes(f.toPath()));
            // Write to the output panel
            View.getSingleton().getOutputPanel().append(contents);
            // Give focus to the Output tab
            View.getSingleton().getOutputPanel().setTabFocus();
        } catch (Exception e) {
            // Something unexpected went wrong, write the error to the log
            LOGGER.error(e.getMessage(), e);
        }
    }

    private RightClickMsgMenu getPopupMsgMenuExample() {
        if (popupMsgMenuExample == null) {
            popupMsgMenuExample = new RightClickMsgMenu(this,
                    Constant.messages.getString(PREFIX + ".popup.title"));
        }
        return popupMsgMenuExample;
    }

    @Override
    public String getAuthor() {
        return Constant.ZAP_TEAM;
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString(PREFIX + ".desc");
    }

    @Override
    public URL getURL() {
        try {
            return new URL(Constant.ZAP_EXTENSIONS_PAGE);
        } catch (MalformedURLException e) {
            return null;
        }
    }

    @Override
    public boolean onHttpRequestSend(HttpMessage msg) {
        return true;
    }

    @Override
    public boolean onHttpResponseReceive(HttpMessage msg) {
        if (frontEndScannerEnabled && msg.getResponseHeader().isHtml()) {
            try {
                String html = msg.getResponseBody().toString();

                Source document = new Source(html);
                List<Element> heads = document.getAllElements("head");
                Element head = heads.isEmpty() ? null : heads.get(0);

                if (head != null) {
                    String injectedContent =
                        "<script type='text/javascript'>"
                        + userScriptsToInject()
                        + frontEndScannerCode()
                        + "</script>";

                    OutputDocument newResponseBody = new OutputDocument(document);
                    int insertPosition = head.getChildElements().get(0).getBegin();
                    newResponseBody.insert(insertPosition, injectedContent);

                    msg.getResponseBody()
                        .setBody(newResponseBody.toString());

                    int newLength = msg.getResponseBody().length();
                    msg.getResponseHeader().setContentLength(newLength);
                } else {
                    LOGGER.error("<head></head> is missing in the response");
                }
            } catch (Exception e) {
                LOGGER.error(e.getMessage(), e);
            }
        }
        return true;
    }

    @Override
    public int getArrangeableListenerOrder() {
        return 0;
    }

    private String frontEndScannerCode() throws IOException {
        Path frontEndScannerPath = Paths.get(FRONT_END_SCANNER);
        return readFromFile(frontEndScannerPath);
    }

    private String userScriptsToInject() throws IOException {
        Path scriptFolderPath = Paths.get(SCRIPTS_FOLDER);
        Stream<String> scriptCodes;
        String result = "";

        try {
            List<String> functionNames = new ArrayList<String>();
            Stream<Path> scriptFilePaths = Files.list(scriptFolderPath);

            scriptCodes = scriptFilePaths
                .map(scriptFileName -> readFromFile(scriptFileName))
                .map(code -> code.getBytes())
                .map(code -> new String(code))
                // `wrapInFunction` has a side-effect: it updates the `functionNames` List
                .map(code -> wrapInFunction(code, functionNames));

            result = scriptCodes.reduce(result, String::concat);
            result += "const SCRIPTS = [ " + String.join(", ", functionNames) + "];";
            return result;
        } catch (UncheckedIOException e) {
            new IOException(e);
        }

        return result;
    }

    private String readFromFile(Path file) throws UncheckedIOException {
        try {
            byte[] content = Files.readAllBytes(file);
            return new String(content);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private String wrapInFunction(String javascriptCode, List<String> functionNames) {
        String id = Long.toString(Math.abs(UUID.randomUUID().getMostSignificantBits()));
        String functionName = "f_" + id;

        functionNames.add(functionName);

        return new String(
            "function " + functionName + " () { " + javascriptCode + " };"
        );
    }
}