package comp3911.cwk2;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

public class PasswordHasher {

  private final static int ITERATIONS = 65536;
  private final static int KEY_LENGTH = 128;

  private final SecureRandom random;

  public PasswordHasher() {
    this.random = new SecureRandom();
  }

  public byte[] generateSalt() {
    byte[] salt = new byte[16];
    random.nextBytes(salt);
    return salt;
  }

  public String encodeSalt(byte[] salt) {
    return Base64.getEncoder().encodeToString(salt);
  }
  public byte[] decodeSalt(String salt) {
    return Base64.getDecoder().decode(salt);
  }

  public String hash(String password, byte[] salt) {
    KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, KEY_LENGTH);

    try {
      SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");

      byte[] hash = factory.generateSecret(spec).getEncoded();
      return Base64.getEncoder().encodeToString(hash);
    } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
      throw new RuntimeException(ex);
    }
  }
}
