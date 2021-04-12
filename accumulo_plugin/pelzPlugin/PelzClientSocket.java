/*
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

package org.apache.accumulo.core.cryptoImpl.pelzPlugin;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;

public class PelzClientSocket 
{
  // initialize socket and input output streams
  private static SocketChannel client = null;
  private static InetSocketAddress hostAddress = null;
  private static boolean client_status = false; //True if connected and False if closed
  private static int buf_size = 1024; //Socket packet size for buffer
  
  public static void connectClient(String address, int port)
  {
	  hostAddress = new InetSocketAddress(address, port);
	  try {
	    client = SocketChannel.open(hostAddress);
	    client_status = true;
	  } catch (IOException err) {
		  System.err.println("I/O Connection Error: " + err.getMessage());
	  }
  }
  
  // Send Request to socket
  public synchronized static String sendRequest(String request)
  {
	  ByteBuffer buffer = ByteBuffer.allocate(buf_size);
	  buffer = ByteBuffer.wrap(request.getBytes());
	  // send request
	  try {
	    client.write(buffer);
	  } catch (IOException err) {
		  System.err.println("I/O Write Error: " + err.getMessage());
	  }
	  
	  //receive message
	  String msg = null;
	  buffer = ByteBuffer.allocate(buf_size);
	  try {
          client.read(buffer);
          } catch (IOException err) {
    	    System.err.println("I/O Read Error: " + err.getMessage());
          }  
	  buffer.flip(); //This changes the ByteBuffer from a read to write state.
          msg = new String(buffer.array()).trim();
	  return msg;
  }

  public static boolean checkClient() {
	  client_status = client.isConnected();
	  return client_status;
  }
  
  // Close Socket Connection
  public static void closeClient()
  {
    try
    {
      client.close();
      System.err.println("Closed");
      client_status = false;
    } catch(IOException err) {
        System.err.println("I/O Closure Error: " + err.getMessage());
    }
  }
  
  public static boolean getClientStatus() {
      return client_status;
    }
}
