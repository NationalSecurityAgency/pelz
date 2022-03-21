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
 *    org.apache.accumulo.core.crypto.CryptoTest.java
 *
 * It was obtained from: https://github.com/apache/accumulo 
 */

package org.apache.accumulo.core.pelz;

import static org.apache.accumulo.core.conf.Property.INSTANCE_CRYPTO_PREFIX;
import static org.apache.accumulo.core.crypto.CryptoUtils.getFileDecrypter;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import org.apache.accumulo.core.classloader.ClassLoaderUtil;
import org.apache.accumulo.core.client.Scanner;
import org.apache.accumulo.core.client.rfile.RFile;
import org.apache.accumulo.core.client.rfile.RFileWriter;
import org.apache.accumulo.core.client.summary.Summarizer;
import org.apache.accumulo.core.client.summary.SummarizerConfiguration;
import org.apache.accumulo.core.client.summary.Summary;
import org.apache.accumulo.core.conf.AccumuloConfiguration;
import org.apache.accumulo.core.conf.ConfigurationCopy;
import org.apache.accumulo.core.conf.DefaultConfiguration;
import org.apache.accumulo.core.conf.Property;
import org.apache.accumulo.core.data.Key;
import org.apache.accumulo.core.data.Value;
import org.apache.accumulo.core.pelz.PelzCryptoService;
import org.apache.accumulo.core.crypto.CryptoEnvironmentImpl;
import org.apache.accumulo.core.crypto.CryptoServiceFactory;
import org.apache.accumulo.core.crypto.CryptoServiceFactory.ClassloaderType;
import org.apache.accumulo.core.crypto.streams.NoFlushOutputStream;
import org.apache.accumulo.core.crypto.CryptoUtils;
import org.apache.accumulo.core.spi.crypto.CryptoEnvironment;
import org.apache.accumulo.core.spi.crypto.CryptoEnvironment.Scope;
import org.apache.accumulo.core.spi.crypto.CryptoService;
import org.apache.accumulo.core.spi.crypto.CryptoService.CryptoException;
import org.apache.accumulo.core.spi.crypto.FileDecrypter;
import org.apache.accumulo.core.spi.crypto.FileEncrypter;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FSDataOutputStream;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.google.common.collect.Iterables;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;

public class PelzCryptoTest {

  private static final SecureRandom random = new SecureRandom();
  private static final int MARKER_INT = 0xCADEFEDD;
  private static final String MARKER_STRING = "1 2 3 4 5 6 7 8 a b c d e f g h ";
  private static Configuration hadoopConf = new Configuration();

  public enum ConfigMode {
    CRYPTO_OFF, CRYPTO_ON, CRYPTO_ON_DISABLED
  }

  @BeforeAll
  public static void setupKeyFiles() throws IOException {
    setupKeyFiles(PelzCryptoTest.class);
  }

  public static void setupKeyFiles(Class<?> testClass) throws IOException {
    FileSystem fs = FileSystem.getLocal(hadoopConf);
    Path aesPath = new Path(keyPath(testClass));
    try (FSDataOutputStream out = fs.create(aesPath)) {
      out.writeUTF("sixteenbytekey"); // 14 + 2 from writeUTF
    }
    try (FSDataOutputStream out = fs.create(new Path(emptyKeyPath(testClass)))) {
      // auto close after creating
      assertNotNull(out);
    }
  }

  @SuppressWarnings("fallthrough")
  public static ConfigurationCopy getAccumuloConfig(ConfigMode configMode, Class<?> testClass) {
    ConfigurationCopy cfg = new ConfigurationCopy(DefaultConfiguration.getInstance());
    switch (configMode) {
      case CRYPTO_ON_DISABLED:
        cfg.set(INSTANCE_CRYPTO_PREFIX.getKey() + "enabled", "false");
        // fall through to set remaining config
      case CRYPTO_ON:
        cfg.set(Property.INSTANCE_CRYPTO_SERVICE,
            "org.apache.accumulo.core.pelz.PelzCryptoService");
        cfg.set(INSTANCE_CRYPTO_PREFIX.getKey() + "key.uri", PelzCryptoTest.keyPath(testClass));
        break;
      case CRYPTO_OFF:
        break;
    }
    return cfg;
  }

  private ConfigurationCopy getAccumuloConfig(ConfigMode configMode) {
    return getAccumuloConfig(configMode, getClass());
  }

  public static String keyPath(Class<?> testClass) {
    return "file:" + System.getProperty("user.dir") + "/target/CryptoTest-testkeyfile.key";
  }

  public static String emptyKeyPath(Class<?> testClass) {
    return "file:" + System.getProperty("user.dir") + "/target/CryptoTest-emptykeyfile.key";
  }

  @Test
  public void simpleGCMTest() throws Exception {
    AccumuloConfiguration conf = getAccumuloConfig(ConfigMode.CRYPTO_ON);

    CryptoService cs = new PelzCryptoService();
    cs.init(conf.getAllPropertiesWithPrefix(Property.INSTANCE_CRYPTO_PREFIX));
    CryptoEnvironment encEnv = new CryptoEnvironmentImpl(Scope.RFILE, null);
    FileEncrypter encrypter = cs.getFileEncrypter(encEnv);
    byte[] params = encrypter.getDecryptionParameters();
    assertNotNull(params);

    ByteArrayOutputStream out = new ByteArrayOutputStream();
    DataOutputStream dataOut = new DataOutputStream(out);
    CryptoUtils.writeParams(params, dataOut);
    OutputStream encrypted = encrypter.encryptStream(dataOut);

    assertNotNull(encrypted);
    DataOutputStream cipherOut = new DataOutputStream(encrypted);

    cipherOut.writeUTF(MARKER_STRING);

    cipherOut.close();
    dataOut.close();
    encrypted.close();
    out.close();

    byte[] cipherText = out.toByteArray();

    // decrypt
    ByteArrayInputStream in = new ByteArrayInputStream(cipherText);
    FileDecrypter decrypter = getFileDecrypter(cs, Scope.RFILE, new DataInputStream(in));
    DataInputStream decrypted = new DataInputStream(decrypter.decryptStream(in));
    String plainText = decrypted.readUTF();
    decrypted.close();
    in.close();

    assertEquals(MARKER_STRING, new String(plainText));
  }

  @Test
  public void testPelzCryptoServiceWAL() throws Exception {
    PelzCryptoService cs = new PelzCryptoService();
    byte[] resultingBytes = encrypt(cs, Scope.WAL, ConfigMode.CRYPTO_ON);

    String stringifiedBytes = Arrays.toString(resultingBytes);
    String stringifiedMarkerBytes = getStringifiedBytes(null, MARKER_STRING, MARKER_INT);

    assertNotEquals(stringifiedBytes, stringifiedMarkerBytes);

    decrypt(resultingBytes, Scope.WAL, ConfigMode.CRYPTO_ON);
  }

  /**
   * PelzCryptoService is configured but only for reading
   */
  @Test
  public void testPelzCryptoServiceWALDisabled() throws Exception {
    PelzCryptoService cs = new PelzCryptoService();
    // make sure we can read encrypted
    byte[] encryptedBytes = encrypt(cs, Scope.WAL, ConfigMode.CRYPTO_ON);
    String stringEncryptedBytes = Arrays.toString(encryptedBytes);
    String stringifiedMarkerBytes = getStringifiedBytes(null, MARKER_STRING, MARKER_INT);
    assertNotEquals(stringEncryptedBytes, stringifiedMarkerBytes);
    decrypt(encryptedBytes, Scope.WAL, ConfigMode.CRYPTO_ON_DISABLED);

    // make sure we don't encrypt when disabled
    byte[] plainBytes = encrypt(cs, Scope.WAL, ConfigMode.CRYPTO_ON_DISABLED);
    String stringPlainBytes = Arrays.toString(plainBytes);
    assertNotEquals(stringEncryptedBytes, stringPlainBytes);
    decrypt(plainBytes, Scope.WAL, ConfigMode.CRYPTO_ON_DISABLED);
  }

  @Test
  public void testPelzCryptoServiceRFILE() throws Exception {
    PelzCryptoService cs = new PelzCryptoService();
    byte[] resultingBytes = encrypt(cs, Scope.RFILE, ConfigMode.CRYPTO_ON);

    String stringifiedBytes = Arrays.toString(resultingBytes);
    String stringifiedMarkerBytes = getStringifiedBytes(null, MARKER_STRING, MARKER_INT);

    assertNotEquals(stringifiedBytes, stringifiedMarkerBytes);

    decrypt(resultingBytes, Scope.RFILE, ConfigMode.CRYPTO_ON);
  }

  /**
   * PelzCryptoService is configured but only for reading
   */
  @Test
  public void testPelzCryptoServiceRFILEDisabled() throws Exception {
    PelzCryptoService cs = new PelzCryptoService();
    // make sure we can read encrypted
    byte[] encryptedBytes = encrypt(cs, Scope.RFILE, ConfigMode.CRYPTO_ON);
    String stringEncryptedBytes = Arrays.toString(encryptedBytes);
    String stringifiedMarkerBytes = getStringifiedBytes(null, MARKER_STRING, MARKER_INT);
    assertNotEquals(stringEncryptedBytes, stringifiedMarkerBytes);
    decrypt(encryptedBytes, Scope.RFILE, ConfigMode.CRYPTO_ON_DISABLED);

    // make sure we don't encrypt when disabled
    byte[] plainBytes = encrypt(cs, Scope.RFILE, ConfigMode.CRYPTO_ON_DISABLED);
    String stringPlainBytes = Arrays.toString(plainBytes);
    assertNotEquals(stringEncryptedBytes, stringPlainBytes);
    decrypt(plainBytes, Scope.RFILE, ConfigMode.CRYPTO_ON_DISABLED);
  }

  @Test
  public void testRFileEncrypted() throws Exception {
    AccumuloConfiguration cryptoOnConf = getAccumuloConfig(ConfigMode.CRYPTO_ON);
    FileSystem fs = FileSystem.getLocal(hadoopConf);
    ArrayList<Key> keys = testData();
    SummarizerConfiguration sumConf =
        SummarizerConfiguration.builder(KeyCounter.class.getName()).build();

    String file = "target/testPelzFile1.rf";
    fs.delete(new Path(file), true);
    try (RFileWriter writer = RFile.newWriter().to(file).withFileSystem(fs)
        .withTableProperties(cryptoOnConf).withSummarizers(sumConf).build()) {
      Value empty = new Value();
      writer.startDefaultLocalityGroup();
      for (Key key : keys) {
        writer.append(key, empty);
      }
    }

    Scanner iter =
        RFile.newScanner().from(file).withFileSystem(fs).withTableProperties(cryptoOnConf).build();
    ArrayList<Key> keysRead = new ArrayList<>();
    iter.forEach(e -> keysRead.add(e.getKey()));
    assertEquals(keys, keysRead);

    Collection<Summary> summaries =
        RFile.summaries().from(file).withFileSystem(fs).withTableProperties(cryptoOnConf).read();
    Summary summary = Iterables.getOnlyElement(summaries);
    assertEquals(keys.size(), (long) summary.getStatistics().get("keys"));
    assertEquals(1, summary.getStatistics().size());
    assertEquals(0, summary.getFileStatistics().getInaccurate());
    assertEquals(1, summary.getFileStatistics().getTotal());

  }

  @Test
  // This test is to ensure when Crypto is configured that it can read unencrypted files
  public void testReadNoCryptoWithCryptoConfigured() throws Exception {
    AccumuloConfiguration cryptoOffConf = getAccumuloConfig(ConfigMode.CRYPTO_OFF);
    AccumuloConfiguration cryptoOnConf = getAccumuloConfig(ConfigMode.CRYPTO_ON);
    FileSystem fs = FileSystem.getLocal(hadoopConf);
    ArrayList<Key> keys = testData();

    String file = "target/testPelzFile2.rf";
    fs.delete(new Path(file), true);
    try (RFileWriter writer =
        RFile.newWriter().to(file).withFileSystem(fs).withTableProperties(cryptoOffConf).build()) {
      Value empty = new Value();
      writer.startDefaultLocalityGroup();
      for (Key key : keys) {
        writer.append(key, empty);
      }
    }

    Scanner iter =
        RFile.newScanner().from(file).withFileSystem(fs).withTableProperties(cryptoOnConf).build();
    ArrayList<Key> keysRead = new ArrayList<>();
    iter.forEach(e -> keysRead.add(e.getKey()));
    assertEquals(keys, keysRead);
  }

  @Test
  public void testMissingConfigProperties() throws ReflectiveOperationException {
    ConfigurationCopy aconf = new ConfigurationCopy(DefaultConfiguration.getInstance());
    Configuration conf = new Configuration(false);
    for (Map.Entry<String,String> e : conf) {
      aconf.set(e.getKey(), e.getValue());
    }
    aconf.set(Property.INSTANCE_CRYPTO_SERVICE,
        "org.apache.accumulo.core.pelz.PelzCryptoService");
    String configuredClass = aconf.get(Property.INSTANCE_CRYPTO_SERVICE.getKey());
    Class<? extends CryptoService> clazz =
        ClassLoaderUtil.loadClass(configuredClass, CryptoService.class);
    CryptoService cs = clazz.getDeclaredConstructor().newInstance();

    assertEquals(PelzCryptoService.class, cs.getClass());
    assertThrows(NullPointerException.class,
        () -> cs.init(aconf.getAllPropertiesWithPrefix(Property.TABLE_PREFIX)));
  }

  @Test
  public void testPelzKeyUtilsGeneratesKey() throws NoSuchAlgorithmException,
      NoSuchProviderException, NoSuchPaddingException, InvalidKeyException {
    // verify valid key sizes (corresponds to 128, 192, and 256 bits)
    for (int i : new int[] {16, 24, 32}) {
      verifyKeySizeForCBC(random, i);
    }
    // verify invalid key sizes
    for (int i : new int[] {1, 2, 8, 11, 15, 64, 128}) {
      assertThrows(InvalidKeyException.class, () -> verifyKeySizeForCBC(random, i));
    }
  }

  // this has to be a separate method, for spotbugs, because spotbugs annotation doesn't seem to
  // apply to the lambda inline
  @SuppressFBWarnings(value = "CIPHER_INTEGRITY", justification = "CBC is being tested")
  private void verifyKeySizeForCBC(SecureRandom sr, int sizeInBytes)
      throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
    java.security.Key key = PelzKeyUtils.generateKey(sr, sizeInBytes);
    Cipher.getInstance("AES/CBC/NoPadding").init(Cipher.ENCRYPT_MODE, key);
  }

  @Test
  public void testPelzKeyUtilsWrapAndUnwrap()
      throws NoSuchAlgorithmException, NoSuchProviderException {
    java.security.Key fek = PelzKeyUtils.generateKey(random, 32);
    String kekPath = "pelz://localhost/7000/5";
    byte[] wrapped = PelzKeyUtils.wrapKey(fek.getEncoded(), kekPath);
    assertFalse(Arrays.equals(fek.getEncoded(), wrapped));
    byte[] unwrapped = PelzKeyUtils.unwrapKey(wrapped, kekPath);
    assertTrue(Arrays.equals(unwrapped, fek.getEncoded()));
  }

  private ArrayList<Key> testData() {
    ArrayList<Key> keys = new ArrayList<>();
    keys.add(new Key("a", "cf", "cq"));
    keys.add(new Key("a1", "cf", "cq"));
    keys.add(new Key("a2", "cf", "cq"));
    keys.add(new Key("a3", "cf", "cq"));
    return keys;
  }

  private <C extends CryptoService> byte[] encrypt(C cs, Scope scope, ConfigMode configMode)
      throws Exception {
    AccumuloConfiguration conf = getAccumuloConfig(configMode);
    cs.init(conf.getAllPropertiesWithPrefix(Property.INSTANCE_CRYPTO_PREFIX));
    CryptoEnvironmentImpl env = new CryptoEnvironmentImpl(scope, null);
    FileEncrypter encrypter = cs.getFileEncrypter(env);
    byte[] params = encrypter.getDecryptionParameters();

    assertNotNull(encrypter, "CryptoService returned null FileEncrypter");

    ByteArrayOutputStream out = new ByteArrayOutputStream();
    DataOutputStream dataOut = new DataOutputStream(out);
    CryptoUtils.writeParams(params, dataOut);
    DataOutputStream encrypted =
        new DataOutputStream(encrypter.encryptStream(new NoFlushOutputStream(dataOut)));
    assertNotNull(encrypted);

    encrypted.writeUTF(MARKER_STRING);
    encrypted.writeInt(MARKER_INT);
    encrypted.close();
    dataOut.close();
    out.close();
    return out.toByteArray();
  }

  private void decrypt(byte[] resultingBytes, Scope scope, ConfigMode configMode) throws Exception {
    try (DataInputStream dataIn = new DataInputStream(new ByteArrayInputStream(resultingBytes))) {
      AccumuloConfiguration conf = getAccumuloConfig(configMode);
      CryptoService cs = CryptoServiceFactory.newInstance(conf, ClassloaderType.JAVA);
      FileDecrypter decrypter = getFileDecrypter(cs, scope, dataIn);

      try (DataInputStream decrypted = new DataInputStream(decrypter.decryptStream(dataIn))) {
        String markerString = decrypted.readUTF();
        int markerInt = decrypted.readInt();

        assertEquals(MARKER_STRING, markerString);
        assertEquals(MARKER_INT, markerInt);
      }
    }
  }

  private String getStringifiedBytes(byte[] params, String s, int i) throws IOException {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    DataOutputStream dataOut = new DataOutputStream(out);

    if (params != null) {
      dataOut.writeInt(params.length);
      dataOut.write(params);
    }
    dataOut.writeUTF(s);
    dataOut.writeInt(i);
    dataOut.close();
    byte[] stringMarkerBytes = out.toByteArray();
    return Arrays.toString(stringMarkerBytes);
  }

  // simple counter to just make sure crypto works with summaries
  public static class KeyCounter implements Summarizer {
    @Override
    public Collector collector(SummarizerConfiguration sc) {
      return new Collector() {

        long keys = 0;

        @Override
        public void accept(Key k, Value v) {
          if (!k.isDeleted())
            keys++;
        }

        @Override
        public void summarize(StatisticConsumer sc) {
          sc.accept("keys", keys);
        }
      };
    }

    @Override
    public Combiner combiner(SummarizerConfiguration sc) {
      return (m1, m2) -> m2.forEach((k, v) -> m1.merge(k, v, Long::sum));
    }
  }

}
