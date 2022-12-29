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

package org.apache.accumulo.core.pelz;

public class PelzObjects {

	public static class Request {
	  private int request_type = 0;
	  private String key_id = null;
	  private String data = null;
		
	  public int getRequestType() {
          return request_type;
    }

	  public void setRequestType(int request_type) {
	        this.request_type = request_type;
	  }
		
	  public String getKeyID() {
	        return key_id;
	  }

	  public void setKeyID(String key_id) {
	        this.key_id = key_id;
	  }
	     
	  public String getData() {
	        return data;
	  }

	  public void setData(String data) {
	        this.data = data;
	  }
  }
	
	public static class Response {
		private String key_id = null;
		private String data = null;
		private String error = null;
		
		public String getKeyID() {
            return key_id;
	  }

    public void setKeyID(String key_id) {
            this.key_id = key_id;
	  }
	      
	  public String getData() {
            return data;
	  }

	  public void setData(String data) {
	          this.data = data;
	  }
	    
	  public String getError() {
	          return error;
	  }

	  public void setError(String error) {
	          this.error = error;
	  }
	}
}
