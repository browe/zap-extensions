/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2012 The ZAP development team
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
package org.zaproxy.zap.extension.quickstart;

import java.net.URL;

import org.apache.commons.httpclient.URI;
import org.apache.log4j.Logger;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.parosproxy.paros.network.HttpStatusCode;
import org.zaproxy.zap.extension.ascan.ExtensionActiveScan;
import org.zaproxy.zap.extension.spider.ExtensionSpider;

public class AttackThread extends Thread {
	
	public enum Progress {notstarted, spider, ascan, failed, complete, stopped }
	
	private ExtensionQuickStart extension;
	private URL url;
    private HttpSender httpSender = null;
    private boolean stopAttack = false;

    private static final Logger logger = Logger.getLogger(AttackThread.class);

	public AttackThread(ExtensionQuickStart ext) {
		this.extension = ext;
	}
	
	public void setURL(URL url) {
		this.url = url;
	}
	
	@Override
	public void run() {
		stopAttack = false;
        try {
    		SiteNode startNode = null;
    		String urlString = url.toString();
    		/*
    		if (! urlString.endsWith("/")) {
    			// TODO very hacky!
    			// If it doesnt end with a slash, add one 
    			startNode = this.accessNode(new URL(urlString + "/"));
    		}
    		*/
			if (startNode == null) {
    			startNode = this.accessNode(this.url);
			}
			
			if (startNode == null) {
				logger.debug("Failed to access URL " + urlString);
				extension.notifyProgress(Progress.failed);
				return;
			}
	        if (stopAttack) {
				logger.debug("Attack stopped manually");
				extension.notifyProgress(Progress.stopped);
	        	return;
	        }

	        if (startNode.isLeaf() && !((SiteNode)startNode.getParent()).isRoot()) {
	        	// Go one level up 
	        	startNode = (SiteNode)startNode.getParent();
	        }

			ExtensionSpider extSpider = (ExtensionSpider) Control.getSingleton().getExtensionLoader().getExtension(ExtensionSpider.NAME);
			if (extSpider == null) {
				logger.error("No spider");
				extension.notifyProgress(Progress.failed);
				return;
			} else {
				extension.notifyProgress(Progress.spider);
				extSpider.startScan(startNode);
			}
			
			try {
				 // Wait for the spider to complete
				while (extSpider.isScanning(startNode, true)) { 
					sleep (500);
					if (this.stopAttack) {
						extSpider.stopScan(startNode);
						break;
					}
				}
			} catch (InterruptedException e) {
				// Ignore
			}
	        if (stopAttack) {
				logger.debug("Attack stopped manually");
				extension.notifyProgress(Progress.stopped);
	        	return;
	        }
	        
	        // Pause before the spider seems to help
	        sleep(2000);

			if (stopAttack) {
				logger.debug("Attack stopped manually");
				extension.notifyProgress(Progress.stopped);
				return;
			}
/*
	        if (startNode.isLeaf() && !((SiteNode)startNode.getParent()).isRoot()) {
	        	// Go one level up 
	        	startNode = (SiteNode)startNode.getParent();
	        }
*/			
			ExtensionActiveScan extAscan = (ExtensionActiveScan) Control.getSingleton().getExtensionLoader().getExtension(ExtensionActiveScan.NAME);
			if (extAscan == null) {
				logger.error("No active scanner");
				extension.notifyProgress(Progress.failed);
				return;
			} else {
				extension.notifyProgress(Progress.ascan);
				extAscan.startScan(startNode);
			}
		
			try {
				 // Wait for the active scanner to complete
				while (extAscan.isScanning(startNode)) { 
					sleep (500);
					if (this.stopAttack) {
						extAscan.stopScan(startNode);
					}
				}
			} catch (InterruptedException e) {
				// Ignore
			}
	        if (stopAttack) {
				logger.debug("Attack stopped manually");
				extension.notifyProgress(Progress.stopped);
	        } else {
				logger.debug("Attack completed");
	        	extension.notifyProgress(Progress.complete);
	        }
        
        } catch (Exception e) {
        	logger.error(e.getMessage(), e);
	        extension.notifyProgress(Progress.failed);
		}
	}
	
	private SiteNode accessNode(URL url) {
		SiteNode startNode = null;
    	// Request the URL
		try {
			HttpMessage msg = new HttpMessage(new URI(url.toString(), true));
			getHttpSender().sendAndReceive(msg,true);
		
	        if (msg.getResponseHeader().getStatusCode() != HttpStatusCode.OK) {
				extension.notifyProgress(Progress.failed);
	            return null;
	        }
	        
	        if (msg.getResponseHeader().isEmpty()) {
	        	return null;
	        }
	        
	        ExtensionHistory extHistory = ((ExtensionHistory)Control.getSingleton().getExtensionLoader().getExtension(ExtensionHistory.NAME));
	        extHistory.addHistory(msg, HistoryReference.TYPE_MANUAL);
	        
	        Model.getSingleton().getSession().getSiteTree().addPath(msg.getHistoryRef());
			
			for (int i=0; i < 10; i++) {
				startNode = Model.getSingleton().getSession().getSiteTree().findNode(new URI(url.toString(), false));
				if (startNode != null) {
					break;
				}
				try {
					sleep (200);
				} catch (InterruptedException e) {
					// Ignore
				}
			}
		} catch (Exception e1) {
			return null;
		}
		return startNode;
	}
	
    private HttpSender getHttpSender() {
		if (httpSender == null) {
            httpSender = new HttpSender(Model.getSingleton().getOptionsParam().getConnectionParam(), true, 
            		HttpSender.MANUAL_REQUEST_INITIATOR);
        }
        return httpSender;
    }

	public void stopAttack() {
		this.stopAttack = true;
	}

}