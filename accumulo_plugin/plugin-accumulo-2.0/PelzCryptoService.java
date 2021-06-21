/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * This code has been modified from its original version. The original file was:
 *    org.apache.accumulo.core.cryptoImpl.AESCryptoService.java
 *
 * It was obtained from: https://github.com/apache/accumulo 
 */

package org.apache.accumulo.core.pelz;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Map;
import java.util.Objects;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.accumulo.core.crypto.CryptoUtils;
import org.apache.accumulo.core.crypto.streams.BlockedInputStream;
import org.apache.accumulo.core.crypto.streams.BlockedOutputStream;
import org.apache.accumulo.core.crypto.streams.DiscardCloseOutputStream;
import org.apache.accumulo.core.crypto.streams.RFileCipherOutputStream;
import org.apache.accumulo.core.spi.crypto.CryptoEnvironment;
import org.apache.accumulo.core.spi.crypto.CryptoService;
import org.apache.accumulo.core.spi.crypto.FileDecrypter;
import org.apache.accumulo.core.spi.crypto.FileEncrypter;
import org.apache.accumulo.core.spi.crypto.NoFileDecrypter;
import org.apache.accumulo.core.spi.crypto.NoFileEncrypter;
import org.apache.accumulo.core.spi.crypto.AESCryptoSerivce:
import org.apache.commons.io.IOUtils;

/*
 * Example implementation of AES encryption for Accumulo
 */
public class PelzCryptoService implements CryptoService {
  // properties required for using this service
  private static final String CRYPTO_PREFIX = "instance.crypto.opts.";
  private static final String KEY_URI = CRYPTO_PREFIX + "key.uri";
  // optional properties
  // defaults to true
  private static final String ENCRYPT_ENABLED = CRYPTO_PREFIX + "enabled";
	
  // Hard coded NoCryptoService.VERSION - this permits the removal of NoCryptoService from the
  // core jar, allowing use of only one crypto service
  private static final String NO_CRYPTO_VERSION = "U+1F47B";

  //Version String for AESCryptoService
  private static final String AES_CRYPTO_VERSION = "U+1F43B";

  private String keyLocation = null;
  private String keyManager = null;
  private SecureRandom sr = null;
  private boolean encryptEnabled = true;

  private static final FileEncrypter DISABLED = new NoFileEncrypter();

  @Override
  public void init(Map<String,String> conf) throws CryptoException {
    String keyLocation =
        Objects.requireNonNull(conf.get(KEY_URI), "Config property " + KEY_URI + " is required.");
    String enabledProp = conf.get(ENCRYPT_ENABLED);
    if (enabledProp != null)
      encryptEnabled = Boolean.parseBoolean(enabledProp);
		    
    String keyMgr = "pelz";
    Objects.requireNonNull(keyLocation,
        "Config property instance.crypto.opts.key.uri is required.");
    this.sr = CryptoUtils.newSha1SecureRandom();
    this.keyManager = keyMgr;
    this.keyLocation = keyLocation;
    if (!PelzKeyUtils.initSocket()) {
      System.err.println("Failed to connect to Pelz.");
    }
  }

  @Override
  public FileEncrypter getFileEncrypter(CryptoEnvironment environment) {
    if (!encryptEnabled) {
      return DISABLED;
    }
    CryptoModule cm;
    switch (environment.getScope()) {
      case WAL:
        cm = new AESCBCCryptoModule(this.keyLocation, this.keyManager);
        return cm.getEncrypter();

      case RFILE:
        cm = new AESGCMCryptoModule(this.keyLocation, this.keyManager);
        return cm.getEncrypter();

      default:
        throw new CryptoException("Unknown scope: " + environment.getScope());
    }
  }

  @Override
  public FileDecrypter getFileDecrypter(CryptoEnvironment environment) {
    CryptoModule cm;
    byte[] decryptionParams = environment.getDecryptionParams();
    if (decryptionParams == null || checkNoCrypto(decryptionParams))
      return new NoFileDecrypter();
    if (checkAESCrypto(decryptionParams))
      throw new CryptoException(
   		  "AESCryptoService File Decrypter not implemented");
    
    ParsedCryptoParameters parsed = parseCryptoParameters(decryptionParams);
    Key fek =
        new SecretKeySpec(PelzKeyUtils.unwrapKey(parsed.getEncFek(), parsed.getKekId()), "AES");
    switch (parsed.getCryptoServiceVersion()) {
      case AESCBCCryptoModule.VERSION:
        cm = new AESCBCCryptoModule(this.keyLocation, this.keyManager);
        return (cm.getDecrypter(fek));
      case AESGCMCryptoModule.VERSION:
        cm = new AESGCMCryptoModule(this.keyLocation, this.keyManager);
        return (cm.getDecrypter(fek));
      default:
        throw new CryptoException(
            "Unknown crypto module version: " + parsed.getCryptoServiceVersion());
    }
  }

  private static boolean checkNoCrypto(byte[] params) {
    byte[] noCryptoBytes = NO_CRYPTO_VERSION.getBytes(UTF_8);
    return Arrays.equals(params, noCryptoBytes);
  }

  private static boolean checkAESCrypto(byte[] params) {
    byte[] AESCryptoBytes = AES_CRYPTO_VERSION.getBytes(UTF_8);
    return Arrays.equals(params, AESCryptoBytes);
  }
  
  static class ParsedCryptoParameters {
    String cryptoServiceName;
    String cryptoServiceVersion;
    String keyManagerVersion;
    String kekId;
    byte[] encFek;

    public String getCryptoServiceName() {
      return cryptoServiceName;
    }

    public void setCryptoServiceName(String cryptoServiceName) {
      this.cryptoServiceName = cryptoServiceName;
    }

    public String getCryptoServiceVersion() {
      return cryptoServiceVersion;
    }

    public void setCryptoServiceVersion(String cryptoServiceVersion) {
      this.cryptoServiceVersion = cryptoServiceVersion;
    }

    public String getKeyManagerVersion() {
      return keyManagerVersion;
    }

    public void setKeyManagerVersion(String keyManagerVersion) {
      this.keyManagerVersion = keyManagerVersion;
    }

    public String getKekId() {
      return kekId;
    }

    public void setKekId(String kekId) {
      this.kekId = kekId;
    }

    public byte[] getEncFek() {
      return encFek;
    }

    public void setEncFek(byte[] encFek) {
      this.encFek = encFek;
    }

  }

  private static byte[] createCryptoParameters(String version, String encryptingKekId,
      String encryptingKeyManager, Key fek) {

    byte[] bytes;
    try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream params = new DataOutputStream(baos)) {
      params.writeUTF(PelzCryptoService.class.getName());
      params.writeUTF(version);
      params.writeUTF(encryptingKeyManager);
      params.writeUTF(encryptingKekId);
      byte[] wrappedFek = PelzKeyUtils.wrapKey(fek.getEncoded(), encryptingKekId);
      params.writeInt(wrappedFek.length);
      params.write(wrappedFek);

      bytes = baos.toByteArray();
    } catch (IOException e) {
      throw new CryptoException("Error creating crypto params", e);
    }
    return bytes;
  }

  private static ParsedCryptoParameters parseCryptoParameters(byte[] parameters) {
    ParsedCryptoParameters parsed = new ParsedCryptoParameters();
    try (ByteArrayInputStream bais = new ByteArrayInputStream(parameters);
        DataInputStream params = new DataInputStream(bais)) {
      parsed.setCryptoServiceName(params.readUTF());
      parsed.setCryptoServiceVersion(params.readUTF());
      parsed.setKeyManagerVersion(params.readUTF());
      parsed.setKekId(params.readUTF());
      int encFekLen = params.readInt();
      byte[] encFek = new byte[encFekLen];
      int bytesRead = params.read(encFek);
      if (bytesRead != encFekLen)
        throw new CryptoException("Incorrect number of bytes read for encrypted FEK");
      parsed.setEncFek(encFek);
    } catch (IOException e) {
      throw new CryptoException("Error creating crypto params", e);
    }
    return parsed;
  }

  /**
   * This interface lists the methods needed by CryptoModules which are responsible for tracking
   * version and preparing encrypters/decrypters for use.
   */
  private interface CryptoModule {
    FileEncrypter getEncrypter();

    FileDecrypter getDecrypter(Key fek);
  }

  public class AESGCMCryptoModule implements CryptoModule {
    private static final String VERSION = "U+1F385";

    private final Integer GCM_IV_LENGTH_IN_BYTES = 12;
    private final Integer KEY_LENGTH_IN_BYTES = 32;

    // 128-bit tags are the longest available for GCM
    private final Integer GCM_TAG_LENGTH_IN_BITS = 16 * 8;
    private final String transformation = "AES/GCM/NoPadding";
    private boolean ivReused = false;
    private String keyLocation;
    private String keyManager;

    public AESGCMCryptoModule(String keyLocation, String keyManager) {
      this.keyLocation = keyLocation;
      this.keyManager = keyManager;
    }

    @Override
    public FileEncrypter getEncrypter() {
      return new AESGCMFileEncrypter();
    }

    @Override
    public FileDecrypter getDecrypter(Key fek) {
      return new AESGCMFileDecrypter(fek);
    }

    public class AESGCMFileEncrypter implements FileEncrypter {

      private byte[] firstInitVector;
      private Key fek;
      private byte[] initVector = new byte[GCM_IV_LENGTH_IN_BYTES];

      AESGCMFileEncrypter() {
        this.fek = PelzKeyUtils.generateKey(sr, KEY_LENGTH_IN_BYTES);
        sr.nextBytes(initVector);
        this.firstInitVector = Arrays.copyOf(initVector, initVector.length);
      }

      @Override
      public OutputStream encryptStream(OutputStream outputStream) throws CryptoException {
        if (ivReused) {
          throw new CryptoException(
              "Key/IV reuse is forbidden in AESGCMCryptoModule. Too many RBlocks.");
        }
        incrementIV(initVector, initVector.length - 1);
        if (Arrays.equals(initVector, firstInitVector)) {
          ivReused = true; // This will allow us to write the final block, since the
          // initialization vector
          // is always incremented before use.
        }

        // write IV before encrypting
        try {
          outputStream.write(initVector);
        } catch (IOException e) {
          throw new CryptoException("Unable to write IV to stream", e);
        }

        Cipher cipher;
        try {
          cipher = Cipher.getInstance(transformation);
          cipher.init(Cipher.ENCRYPT_MODE, fek,
              new GCMParameterSpec(GCM_TAG_LENGTH_IN_BITS, initVector));
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException
            | InvalidAlgorithmParameterException e) {
          throw new CryptoException("Unable to initialize cipher", e);
        }

        RFileCipherOutputStream cos =
            new RFileCipherOutputStream(new DiscardCloseOutputStream(outputStream), cipher);
        // Prevent underlying stream from being closed with DiscardCloseOutputStream
        // Without this, when the crypto stream is closed (in order to flush its last bytes)
        // the underlying RFile stream will *also* be closed, and that's undesirable as the
        // cipher
        // stream is closed for every block written.
        return new BlockedOutputStream(cos, cipher.getBlockSize(), 1024);
      }

      /**
       * Because IVs can be longer than longs, this increments arbitrarily sized byte arrays by 1,
       * with a roll over to 0 after the max value is reached.
       *
       * @param iv
       *          The iv to be incremented
       * @param i
       *          The current byte being incremented
       */
      void incrementIV(byte[] iv, int i) {
        iv[i]++;
        if (iv[i] == 0) {
          if (i == 0)
            return;
          else {
            incrementIV(iv, i - 1);
          }
        }

      }

      @Override
      public byte[] getDecryptionParameters() {
        return createCryptoParameters(VERSION, keyLocation, keyManager, fek);
      }
    }

    public class AESGCMFileDecrypter implements FileDecrypter {
      private Key fek;

      AESGCMFileDecrypter(Key fek) {
        this.fek = fek;
      }

      @Override
      public InputStream decryptStream(InputStream inputStream) throws CryptoException {
        byte[] initVector = new byte[GCM_IV_LENGTH_IN_BYTES];
        try {
          IOUtils.readFully(inputStream, initVector);
        } catch (IOException e) {
          throw new CryptoException("Unable to read IV from stream", e);
        }

        Cipher cipher;
        try {
          cipher = Cipher.getInstance(transformation);
          cipher.init(Cipher.DECRYPT_MODE, fek,
              new GCMParameterSpec(GCM_TAG_LENGTH_IN_BITS, initVector));

        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException
            | InvalidAlgorithmParameterException e) {
          throw new CryptoException("Unable to initialize cipher", e);
        }

        CipherInputStream cis = new CipherInputStream(inputStream, cipher);
        return new BlockedInputStream(cis, cipher.getBlockSize(), 1024);
      }
    }
  }

  public class AESCBCCryptoModule implements CryptoModule {
    public static final String VERSION = "U+1f381";
    private final Integer IV_LENGTH_IN_BYTES = 16;
    private final Integer KEY_LENGTH_IN_BYTES = 32;
    private final String transformation = "AES/CBC/NoPadding";
    private String keyLocation;
    private String keyManager;

    public AESCBCCryptoModule(String keyLocation, String keyManager) {
      this.keyLocation = keyLocation;
      this.keyManager = keyManager;
    }

    @Override
    public FileEncrypter getEncrypter() {
      return new AESCBCFileEncrypter();
    }

    @Override
    public FileDecrypter getDecrypter(Key fek) {
      return new AESCBCFileDecrypter(fek);
    }

    public class AESCBCFileEncrypter implements FileEncrypter {

      private Key fek = PelzKeyUtils.generateKey(sr, KEY_LENGTH_IN_BYTES);
      private byte[] initVector = new byte[IV_LENGTH_IN_BYTES];

      @Override
      public OutputStream encryptStream(OutputStream outputStream) throws CryptoException {

        sr.nextBytes(initVector);
        try {
          outputStream.write(initVector);
        } catch (IOException e) {
          throw new CryptoException("Unable to write IV to stream", e);
        }

        Cipher cipher;
        try {
          cipher = Cipher.getInstance(transformation);
          cipher.init(Cipher.ENCRYPT_MODE, fek, new IvParameterSpec(initVector));
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException
            | InvalidAlgorithmParameterException e) {
          throw new CryptoException("Unable to initialize cipher", e);
        }

        CipherOutputStream cos = new CipherOutputStream(outputStream, cipher);
        return new BlockedOutputStream(cos, cipher.getBlockSize(), 1024);
      }

      @Override
      public byte[] getDecryptionParameters() {
        return createCryptoParameters(VERSION, keyLocation, keyManager, fek);
      }
    }

    public class AESCBCFileDecrypter implements FileDecrypter {
      private Key fek;

      AESCBCFileDecrypter(Key fek) {
        this.fek = fek;
      }

      @Override
      public InputStream decryptStream(InputStream inputStream) throws CryptoException {
        byte[] initVector = new byte[IV_LENGTH_IN_BYTES];
        try {
          IOUtils.readFully(inputStream, initVector);
        } catch (IOException e) {
          throw new CryptoException("Unable to read IV from stream", e);
        }

        Cipher cipher;
        try {
          cipher = Cipher.getInstance(transformation);
          cipher.init(Cipher.DECRYPT_MODE, fek, new IvParameterSpec(initVector));
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException
            | InvalidAlgorithmParameterException e) {
          throw new CryptoException("Unable to initialize cipher", e);
        }

        CipherInputStream cis = new CipherInputStream(inputStream, cipher);
        return new BlockedInputStream(cis, cipher.getBlockSize(), 1024);
      }
    }
  }
}
