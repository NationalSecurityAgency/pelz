/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

/*
 * This code has been modified from its original version. The original file was:
 *    org.apache.accumulo.core.cryptoImpl.AESKeyUtils.java
 *
 * It was obtained from: https://github.com/apache/accumulo 
 */
package org.apache.accumulo.core.cryptoImpl.pelzPlugin;

import java.security.Key;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.spec.SecretKeySpec;

import org.apache.accumulo.core.spi.crypto.CryptoService;

import com.google.gson.Gson;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;

public class PelzKeyUtils {

  private static String hostname = "127.0.0.1";  //Pelz socket server address
  private static int port = 10600; // Pelz socket port address
  private static Object delay = new Object();

  public static void staticWait(int t) {
    synchronized (delay) {
      try {
        delay.wait(t);
      } catch (Exception e) {}
    }
  }

  public static void startSocket() {
	do {
	  PelzClientSocket.connectClient(hostname, port);
	} while (!PelzClientSocket.getClientStatus());
  }
  
  public static void endSocket() {
	do {
	  PelzClientSocket.closeClient();
	} while (PelzClientSocket.getClientStatus());
  }
	  
  public static boolean initSocket() {
    startSocket();
    return true;
  }
	  
  public static byte[] pelzRequest(PelzObjects.Request req) {
	byte[] resp = null;
	String receive = null;
	PelzObjects.Response msg = new PelzObjects.Response();
	Gson gson = new Gson();
	String send = gson.toJson(req);
	if (!PelzClientSocket.checkClient()) {
	  startSocket();
	  System.out.println("Restart Socket Connection");
	  staticWait(500);
	  System.out.println("Socket Connection Restarted");
	}
	receive = PelzClientSocket.sendRequest(send);
	if (receive == null) {
	  System.out.println("Message is NULL");
	  return resp;
	}
	msg = gson.fromJson(receive, PelzObjects.Response.class);
	if (msg.getError() != null)
	  throw new CryptoService.CryptoException(msg.getError());
	if (req.getRequestType() == 1) {
	  msg.setEncOut(msg.getEncOut().substring(0, (msg.getEncOutLen() - 1)));
	  resp = Base64.getDecoder().decode(msg.getEncOut());
	}
	else if(req.getRequestType() == 2){
	  msg.setDecOut(msg.getDecOut().substring(0, (msg.getDecOutLen() - 1)));
	  resp = Base64.getDecoder().decode(msg.getDecOut());
	}
	return resp;
  }

  public static Key generateKey(SecureRandom sr, int size) {
    byte[] bytes = new byte[size];
    sr.nextBytes(bytes);
    return new SecretKeySpec(bytes, "AES");
  }

  @SuppressFBWarnings(value = "CIPHER_INTEGRITY",
      justification = "integrity not needed for key wrap")
  public static byte[] unwrapKey(byte[] fek, String keyId) {
    byte[] result = null;
    PelzObjects.Request req = new PelzObjects.Request();
    req.setRequestType(2);
    req.setKeyID(keyId);
    req.setKeyIDLen(keyId.length());
    String dec_data = Base64.getEncoder().encodeToString(fek);
    dec_data = dec_data.concat(System.getProperty("line.separator"));
    req.setDecData(dec_data);
    req.setDecDataLen(dec_data.length());
    try {
      result = pelzRequest(req);
    } catch (CryptoService.CryptoException e) {
        System.err.println(e);
        System.out.println("Error with Pelz Request");
    }
    return result;
  }

  @SuppressFBWarnings(value = "CIPHER_INTEGRITY",
      justification = "integrity not needed for key wrap")
  public static byte[] wrapKey(byte[] fek, String keyId) {
    byte[] result = null;
    PelzObjects.Request req = new PelzObjects.Request();
    req.setRequestType(1);
    req.setKeyID(keyId);
    req.setKeyIDLen(keyId.length());
    String enc_data = Base64.getEncoder().encodeToString(fek);
    enc_data = enc_data.concat(System.getProperty("line.separator"));
    req.setEncData(enc_data);
    req.setEncDataLen(enc_data.length());
    try {
      result = pelzRequest(req);
    } catch (CryptoService.CryptoException e) {
        System.err.println(e);
        System.out.println("Error with Pelz Request");
    }
    return result;
  }
}
