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

public class PelzObjects {

	public static class Request {
		private int request_type = 0;
		private String key_id = null;
		private int key_id_len = 0;
		private String enc_data = null;
		private int enc_data_len = 0;
		private String dec_data = null;
		private int dec_data_len = 0;
		
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
	      
	    public int getKeyIDLen() {
	        return key_id_len;
	      }

	    public void setKeyIDLen(int key_id_len) {
	        this.key_id_len = key_id_len;
	      }

	    public String getEncData() {
	        return enc_data;
	      }

	    public void setEncData(String enc_data) {
	        this.enc_data = enc_data;
	      }
	      
	    public int getEncDataLen() {
	        return enc_data_len;
	      }

	    public void setEncDataLen(int enc_data_len) {
	        this.enc_data_len = enc_data_len;
	    }
	    
	    public String getDecData() {
	        return dec_data;
	      }

	    public void setDecData(String dec_data) {
	        this.dec_data = dec_data;
	      }
	      
	    public int getDecDataLen() {
	        return dec_data_len;
	      }

	    public void setDecDataLen(int dec_data_len) {
	        this.dec_data_len = dec_data_len;
	    }
	}
	
	public static class Response {
		private String key_id = null;
		private int key_id_len = 0;
		private String enc_out = null;
		private int enc_out_len = 0;
		private String dec_out = null;
		private int dec_out_len = 0;
		private String error = null;
		
		public String getKeyID() {
	        return key_id;
	      }

	    public void setKeyID(String key_id) {
	        this.key_id = key_id;
	      }
	      
	    public int getKeyIDLen() {
	        return key_id_len;
	      }

	    public void setKeyIDLen(int key_id_len) {
	        this.key_id_len = key_id_len;
	      }

	    public String getEncOut() {
	        return enc_out;
	      }

	    public void setEncOut(String enc_out) {
	        this.enc_out = enc_out;
	      }
	      
	    public int getEncOutLen() {
	        return enc_out_len;
	      }

	    public void setEncOutLen(int enc_out_len) {
	        this.enc_out_len = enc_out_len;
	    }
	    
	    public String getDecOut() {
	        return dec_out;
	      }

	    public void setDecOut(String dec_out) {
	        this.dec_out = dec_out;
	      }
	      
	    public int getDecOutLen() {
	        return dec_out_len;
	      }

	    public void setDecOutLen(int dec_out_len) {
	        this.dec_out_len = dec_out_len;
	    }
	    
	    public String getError() {
	        return error;
	      }

	    public void setError(String error) {
	        this.error = error;
	      }
	}
}
