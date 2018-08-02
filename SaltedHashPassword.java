package PWD;

//import java.security.SecureRandom;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.SecretKeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Random;

import javax.xml.bind.DatatypeConverter;

public class SaltedHashPassword
{
	// The goal of this class is to have a simplified Salted Hash password creator and validator
	// It is my belief that the most secure method for the salted hash combo is to have the salt hard coded into your application
	//   and store the salted-hash in the database. A sttic method, generateSalt, is included for creating a salt string if you need it.
	
	// Why? if you store the HASH:SALT combo, and a hacker gets access to the database, they now have the hash and the salt
	// 	however if the salt is hard coded in your app, and only the result Salted-Hash is stored in your database
	// 	the hacker has to get the code, find the salt and get access to your database as well.
	
	// Just having hashed passwords is a great start, it prevents your own users and employees from seeing passwords.
	// It is my opinion that salting a hash is to protect from hackers, and as stated before, if the salt and the hash 
	//  are both saved in the database, I believe you are just making your database the only obstacle for hackers.
	
	// Therefore this class assumes that you have the SALT in your code outside of this class.
	// This class is based on the work and ideas of Taylor Hornby taylor@defuse.ca
	//   https://github.com/defuse/password-hashing

	@SuppressWarnings("serial")
	static public class InvalidHashException 
		extends Exception
	{
		public InvalidHashException(String message)
		{
			super(message);
		}
		public InvalidHashException(String message, Throwable source)
		{
			super(message, source);
		}
	}

	@SuppressWarnings("serial")
	static public class CannotPerformOperationException 
		extends Exception
	{
		public CannotPerformOperationException(String message)
		{
			super(message);
		}
		public CannotPerformOperationException(String message, Throwable source)
		{
			super(message, source);
		}
	}

	public static final String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA1";

	// These constants may be changed to make your usage more unique
	public static final int	SALT_BYTE_SIZE		= 8;
	public static final int	HASH_BYTE_SIZE		= 8;
	public static final int	PBKDF2_ITERATIONS	= 64000;
	
	
	private String Salt_by;				// The salt as a String that you have saved for this user, passed into this class
										// as a string so it can be saved in a database
	private String PWD_str = "";		// The Password passed into this class
	private String Hash_by;				// The Hash created by this class
	private boolean Valid_b = false;	// boolean set on instantiation - hash, password and salt combo match

	// These constants define the encoding and may not be changed.
	// public static final int	HASH_SECTIONS			= 5;
	public static final int	HASH_ALGORITHM_INDEX	= 0;
	public static final int	ITERATION_INDEX			= 1;
	public static final int	HASH_SIZE_INDEX			= 2;
	public static final int	SALT_INDEX				= 3;
	public static final int	PBKDF2_INDEX			= 4;
	


	public SaltedHashPassword()
		{
		}
	
	public SaltedHashPassword( String yourSalt)
		{
			Salt_by = yourSalt;
		}
	
	public SaltedHashPassword(String password, String yourSalt)
		{
			Salt_by = yourSalt;
			PWD_str = password;
			
			// TODO handle user interface or logging of exceptions
			try
				{
					Hash_by = createHash(password, yourSalt);
				} 
			catch (CannotPerformOperationException e)
				{
					e.printStackTrace();
				}
		}
	
	public SaltedHashPassword(String password, String yourSalt, String Hash)
		{
			Salt_by = yourSalt;
			PWD_str = password;
			Hash_by = Hash;
			
			// TODO handle user interface or logging of exceptions
			try
				{
					Valid_b = verifyPassword();
				} 
			catch (CannotPerformOperationException e)
				{
					e.printStackTrace();
				} 
			catch (InvalidHashException e)
				{
					e.printStackTrace();
				}
		}
	

	
	public  String createHash() 
			throws CannotPerformOperationException
		{
			return createHash(PWD_str.toCharArray(), Salt_by);
		}

	public static String createHash(String password, String yourSalt) 
			throws CannotPerformOperationException
		{ // assumes that the salt passed in is already established and is the same size as the one in this class
			return createHash(password.toCharArray(), yourSalt);
		}

	public static String createHash(char[] password, String tempSalt) 
			throws CannotPerformOperationException
		{
			// Generate a random salt
			// SecureRandom random = new SecureRandom();
	
			// Hash the password
			byte[] HashSalt = fromBase64(tempSalt);
			byte[] hash = pbkdf2(password, HashSalt, PBKDF2_ITERATIONS, HASH_BYTE_SIZE);
			
			// int hashSize = hash.length;
	
			// format: algorithm:iterations:hashSize:salt:hash
			// String parts = "sha1:" + PBKDF2_ITERATIONS + ":" + hashSize + ":" + toBase64(tempSalt) + ":" + toBase64(hash);
			return toBase64(hash);
		}
	

	public boolean verifyPassword()
			throws CannotPerformOperationException, InvalidHashException
		{
			return verifyPassword(PWD_str.toCharArray(), Salt_by, Hash_by);
		}
	
	public boolean verifyPassword(String password, String correctHash)
			throws CannotPerformOperationException, InvalidHashException
		{
			return verifyPassword(password.toCharArray(), Salt_by, correctHash);
		}
			
	public static boolean verifyPassword(String password, String tempSalt, String correctHash)
			throws CannotPerformOperationException, InvalidHashException
		{
			return verifyPassword(password.toCharArray(), tempSalt, correctHash);
		}

	public static boolean verifyPassword(char[] password, String tempSalt, String correctHash)
			throws CannotPerformOperationException, InvalidHashException
	{
		// Decode the hash into its parameters
//		String[] params = correctHash.split(":");
//		if (params.length != HASH_SECTIONS)
//			{
//				throw new InvalidHashException("Fields are missing from the password hash.");
//			}

		// Currently, Java only supports SHA1.
//		if (!params[HASH_ALGORITHM_INDEX].equals("sha1"))
//		{
//			throw new CannotPerformOperationException("Unsupported hash type.");
//		}

//		int iterations = 0;
//		try
//			{
//				iterations = Integer.parseInt(params[ITERATION_INDEX]);
//			} 
//		catch (NumberFormatException ex)
//			{
//				throw new InvalidHashException("Could not parse the iteration count as an integer.", ex);
//			}

		// if (iterations < 1)
//			{
//				throw new InvalidHashException("Invalid number of iterations. Must be >= 1.");
//			}

		byte[] salt = null;
		try
			{
				salt = fromBase64(tempSalt);
			} 
		catch (IllegalArgumentException ex)
			{
				throw new InvalidHashException("Base64 decoding of salt failed.", ex);
			}

		byte[] hash = null;
		try
			{
				hash = fromBase64(correctHash);
			} 
		catch (IllegalArgumentException ex)
			{
				throw new InvalidHashException("Base64 decoding of pbkdf2 output failed.", ex);
			}

		if (HASH_BYTE_SIZE != hash.length)
			{
				throw new InvalidHashException("Hash length doesn't match stored hash length.");
			}

		// Compute the hash of the provided password, using the same salt,
		// iteration count, and hash length
		byte[] testHash = pbkdf2(password, salt, PBKDF2_ITERATIONS, hash.length);
		
		// Compare the hashes in constant time. The password is correct if both hashes match.
		
		return slowEquals(hash, testHash);
	}

	private static boolean slowEquals(byte[] a, byte[] b)
		{
			int diff = a.length ^ b.length;
			for (int i = 0; i < a.length && i < b.length; i++)
				diff |= a[i] ^ b[i];
			return diff == 0;
		}

	private static byte[] pbkdf2(char[] password, byte[] salt, int iterations, int bytes) 
			throws CannotPerformOperationException
		{
			try
			{
				PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, bytes * 8);
				SecretKeyFactory skf = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);
				return skf.generateSecret(spec).getEncoded();
			} catch (NoSuchAlgorithmException ex)
			{
				throw new CannotPerformOperationException("Hash algorithm not supported.", ex);
			} catch (InvalidKeySpecException ex)
			{
				throw new CannotPerformOperationException("Invalid key spec.", ex);
			}
		}

	private static byte[] fromBase64(String hex) throws IllegalArgumentException
		{
			return DatatypeConverter.parseBase64Binary(hex);
		}

	private static String toBase64(byte[] array)
		{
			return DatatypeConverter.printBase64Binary(array);
		}
	
	  /**
	   * Returns a random salt to be used to hash a password.
	   * I do not recommend that you save this salt string in your database anywhere
	   * I recommend that you hard code it in a constant somewhere
	   * This method is just provided so you can create it for the first time
	   *  
	   * @return a SaltBytes_int bytes of random salt YUM
	   */
	  public static String generateSalt() 
	  	{
	        SecureRandom random = new SecureRandom();
	        byte bytes[] = new byte[SALT_BYTE_SIZE]; 
	        random.nextBytes(bytes);
	        return toBase64(bytes);
	    }

	  /**
	   * Generates a random password of a given length, using letters and digits.
	   *
	   * @param length the length of the password
	   *
	   * @return a random password
	   */
	  public static String generateRandomPassword(int length) 
		  {
			Random RANDOM = new SecureRandom();
		    StringBuilder sb = new StringBuilder(length);
		    for (int i = 0; i < length; i++) {
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
}
