package PWD;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Random;

//import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.xml.bind.DatatypeConverter;

import PWD.SaltedHashPassword.CannotPerformOperationException;
import PWD.SaltedHashPassword.InvalidHashException;

public class PWDTests
{
	private static final Random RANDOM = new SecureRandom();
	  private static final int ITERATIONS = 64000;
	  private static final int KEY_LENGTH = 256;
	  private static final int SALT_LENGTH = 16;

	public static void main(String[] args)
	{
		// RunTests();
				String tempPWD = SaltedHashPassword.generateRandomPassword(8); //"test";
				System.out.println("PWD: " + tempPWD);
				String tempSalt = SaltedHashPassword.generateSalt();
				System.out.println("Salt: " + tempSalt);

				try
					{
						String tempHash= SaltedHashPassword.createHash(tempPWD,tempSalt);
						System.out.println("hash: " + tempHash);
						System.out.println(SaltedHashPassword.verifyPassword(tempPWD,tempSalt,tempHash));
						
						System.out.println("Manual Test: " + SaltedHashPassword.verifyPassword("test","i2vLLoaKTyo=","9zTxJjMOYHM="));
						
						SaltedHashPassword SPWD = new SaltedHashPassword(tempPWD,tempSalt,tempHash);
						
						System.out.println("New Test: " + SPWD.verifyPassword()); // used after instantiation
						
						System.out.println("salt already set Test: " + SPWD.verifyPassword(tempPWD,tempHash)); // used after salt already set
					} 
				catch (CannotPerformOperationException e)
					{
						e.printStackTrace();
					}
				catch (InvalidHashException e)
					{
						// TODO Auto-generated catch block
						e.printStackTrace();
					}

	}
	
	private static void RunTests()
	{
		byte[] Salt = generateSalt(SALT_LENGTH);
		String PWD = generateRandomPassword(6); //"password".toCharArray();
		byte[] Hash = hash(PWD.toCharArray(), Salt);
				
		System.out.println("Salt: " + Salt);
		System.out.println("PWD: " + PWD);
		System.out.println("HASH:  " + Hash);
		System.out.println(isExpectedPassword(PWD.toCharArray(), Salt, Hash));
		
		Hash = hash(PWD.toCharArray(), Salt);
		System.out.println("HASH2: " + Hash);
		System.out.println(isExpectedPassword(PWD.toCharArray(), Salt, Hash));
		
		Hash = hash(PWD.toCharArray(), Salt);
		System.out.println("HASH3: " + Hash);
		System.out.println(isExpectedPassword(PWD.toCharArray(), Salt, Hash));
		
		
		System.out.print(Hash.toString() + " - ");
		System.out.println(fromBase64(Hash.toString()) );
		System.out.println(isExpectedPassword("hXEWwb".toCharArray(), "[B@2ed3cae0".getBytes(), "[B@52ac5024".getBytes() ) );
		System.out.println(isExpectedPassword("xlk4VE".toCharArray(), "[B@2ed3cae0".getBytes(), "[B@52ac5024".getBytes() ) );


		System.out.println(isExpectedPassword("bpbLwE".toCharArray(), "[B@52ac5024".getBytes(), "[B@2ec195e3".getBytes() ) );
		System.out.println(isExpectedPassword("bpbLwE".toCharArray(), "[B@52ac5024".getBytes(), "[B@27578210".getBytes() ) );
		System.out.println(isExpectedPassword("bpbLwE".toCharArray(), "[B@52ac5024".getBytes(), "[B@1b65d9bd".getBytes() ) );
	}

    private static byte[] fromBase64(String hex)
            throws IllegalArgumentException
        {
            return DatatypeConverter.parseBase64Binary(hex);
        }
    
	  /**
	   * Returns a random salt to be used to hash a password.
	   *
	   * @return a SaltBytes_int bytes of random salt YUM
	   */
	  public static byte[] generateSalt(int SaltBytes_int) 
	  	{
	        SecureRandom random = new SecureRandom();
	        byte bytes[] = new byte[SaltBytes_int]; 
	        random.nextBytes(bytes);
	        return bytes;
	    }
	  
	  /**
	   * 
	   * @param length Password length returned
	   * @return a randomly generated password string of length length_int
	   */
	  public static String generateRandomPassword(int length_int) {
		    StringBuilder sb = new StringBuilder(length_int);
		    for (int i = 0; i < length_int; i++) {
		      int c = RANDOM.nextInt(62);
		      if (c <= 9) {
		        sb.append(String.valueOf(c));
		      } else if (c < 36) {
		        sb.append((char) ('a' + c - 10));
		      } else {
		        sb.append((char) ('A' + c - 36));
		      }
		    }
		    return sb.toString();
		  }
	  
	  /**
	   * Returns a salted and hashed password using the provided hash.<br>
	   * Note - side effect: the password is destroyed (the char[] is filled with zeros)
	   *
	   * @param password the password to be hashed
	   * @param salt     a 16 bytes salt, ideally obtained with the getNextSalt method
	   *
	   * @return the hashed password with a pinch of salt
	   */
	  public static byte[] hash(char[] password, byte[] salt) {
	    PBEKeySpec spec = new PBEKeySpec(password, salt, ITERATIONS, KEY_LENGTH);
	    Arrays.fill(password, Character.MIN_VALUE);
	    try 
		    {
		      SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
		      return skf.generateSecret(spec).getEncoded();
		    } 
	    catch (NoSuchAlgorithmException | InvalidKeySpecException e) 
		    {
		      throw new AssertionError("Error while hashing a password: " + e.getMessage(), e);
		    } 
	    finally 
		    {
		      spec.clearPassword();
		    }
	  }
	  
	  
	  /**
	   * Returns true if the given password and salt match the hashed value, false otherwise.<br>
	   * Note - side effect: the password is destroyed (the char[] is filled with zeros)
	   *
	   * @param password     the password to check
	   * @param salt         the salt used to hash the password
	   * @param expectedHash the expected hashed value of the password
	   *
	   * @return true if the given password and salt match the hashed value, false otherwise
	   */
	  public static boolean isExpectedPassword(char[] password, byte[] salt, byte[] expectedHash) {
	    byte[] pwdHash = hash(password, salt);
	    Arrays.fill(password, Character.MIN_VALUE);
	    if (pwdHash.length != expectedHash.length) return false;
	    for (int i = 0; i < pwdHash.length; i++) {
	      if (pwdHash[i] != expectedHash[i]) return false;
	    }
	    return true;
	  }
}
