import java.io.*;
import java.security.Key;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;

import java.security.KeyFactory;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.RSAPrivateKeySpec;

import java.security.DigestInputStream;
import java.security.MessageDigest;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.math.BigInteger;

import java.util.Scanner;


public class Sender 
{
  private static int BUFFER_SIZE = 32 * 1024;
  
  public static void main(String[] args) throws Exception 
  {
    //read the keys from the files
    PrivateKey xPrivKey = readPrivKeyFromFile("XPrivate.key");
    SecretKeySpec symKey = readSymKeyFromFile("symmetric.key");
    
    //Ask for input name of message file
    Scanner input = new Scanner(System.in);
    System.out.println("Input the name of the message file:");
    String msgFileName = input.nextLine();
    
    //SHA256 the message & print
    msgDigest(msgFileName);
    
    //Encrypt message.dd using RSA encryption with the X private key
    encryptRSA("message.dd", xPrivKey, msgFileName);
    
    //encrypt message.ds-msg using AES with the symmetric key
    encryptAES("message.ds-msg", symKey);

  }//End main
  
  
  /**
   * Calculating the digital digest (SHA256) of the message file
   */
  public static void msgDigest(String msgFileName) throws Exception 
  {
    BufferedInputStream file = new BufferedInputStream(new FileInputStream(msgFileName));
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    DigestInputStream in = new DigestInputStream(file, md);
    int i;
    byte[] buffer = new byte[BUFFER_SIZE];
    do {
      i = in.read(buffer, 0, BUFFER_SIZE);
    } while (i == BUFFER_SIZE);
    md = in.getMessageDigest();
    in.close();

    byte[] hash = md.digest();

    //Print the hashed message
    System.out.println("\nDigit digest of the message (hash value):");
    print(hash);    

    //Then save the hashed message to a file
    saveToFile("message.dd", hash, false);
    
  }//End msgDigest()
  
  
  /**
   * Calculating the RSA encryption of the digital digest (SHA256)
   */
  public static void encryptRSA(String hashFileName, PrivateKey xPrivKey, 
                                String msgFileName) throws Exception 
  {
    Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
    SecureRandom random = new SecureRandom();
    InputStream in = new FileInputStream(hashFileName);
    
    //Encrypt the hash value with RSA encryption
    byte[] hashContents = new byte[32];
    in.read(hashContents);
    in.close();
    
    cipher.init(Cipher.ENCRYPT_MODE, xPrivKey, random);
    byte[] cipherText = cipher.doFinal(hashContents);
    
    //Print the RSA encrypted hash
    System.out.println("RSA encrypted cypher text of the SHA256:");
    print(cipherText);
    
    //Then save RSA cipher text to a file with the message at the end
    appendMsg( "message.ds-msg", cipherText, msgFileName);
  }//End encryptRSA()
  
  
  /**
   * Appends the message to the String from the parameter
   */
  public static void appendMsg(String encryptFileName, byte[] cipherText,
                               String msgFileName) throws Exception 
  {
    InputStream in = new FileInputStream(msgFileName);
    byte[] msgContents = new byte[BUFFER_SIZE];
    int bytesRead = 0;
    
    //RSA encrypted hash
    saveToFile(encryptFileName, cipherText, false);
    
    //Message
    while( (bytesRead = in.read(msgContents)) != -1 )
    {
      if(bytesRead == BUFFER_SIZE)
      {
         saveToFile(encryptFileName, msgContents, true);
      }
      else //Adjust array before saving to file
      {
         byte[] tempRemains = new byte[bytesRead];
         
         for(int parser = 0; parser < bytesRead; parser++)
            tempRemains[parser] = msgContents[parser];
         
         saveToFile(encryptFileName, tempRemains, true);
      }
      
    }//End while - buffer each block
    in.close();
  }//End appendMsg()
  
  
  /**
   * Encrpts the RSA encrypted message with AES encryption using the symmetric key
   */
  public static void encryptAES(String rsaFileName, SecretKeySpec symKey) throws Exception 
  {
    Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding", "SunJCE");
    cipher.init(Cipher.ENCRYPT_MODE, symKey);
    
    InputStream in = new FileInputStream(rsaFileName);
    byte[] rsaContents = new byte[BUFFER_SIZE],
           cipherText = new byte[BUFFER_SIZE];
    boolean firstBlock = true,
            append = true;
    int bytesRead = 0;
    
    while( (bytesRead = in.read(rsaContents)) != -1 )
    {
      append = true;
      if(firstBlock)
      {
         firstBlock = false;
         append = false;
      }
      
      if(bytesRead == BUFFER_SIZE)
      {
         cipherText = cipher.update(rsaContents);
         saveToFile("message.aescipher", cipherText, append);
      }
      else //Adjust array before saving to file
      {
         byte[] tempRemains = new byte[bytesRead];
         
         for(int parser = 0; parser < bytesRead; parser++)
            tempRemains[parser] = rsaContents[parser];
         
         cipherText = cipher.doFinal(tempRemains);
         saveToFile("message.aescipher", cipherText, append);
      }
      
    }//End while - buffer each block
    in.close();
    
  }//End encryptAES()
  
  
  /**
   * Prints out the array in the parameter
   */
  public static void print(byte[] arrayToPrint) //throws Exception 
  {
    for (int k=0, j=0; k < arrayToPrint.length; k++, j++) 
    {
      System.out.format("%2X ", new Byte(arrayToPrint[k]) ) ;
      
      if (j >= 15) 
      {
        System.out.println("");
        j=-1;
      }
    }
    System.out.println("");
  }//End print()
  
  
  /**
    * save the contents of the byte array to file
    */
   public static void saveToFile(String fileName, byte[] contents,
                                 boolean appendToFile) throws IOException 
   {
      //Open file
      OutputStream out = null;
      if(appendToFile)
         out = new FileOutputStream(fileName, appendToFile);
      else
         out = new FileOutputStream(fileName);
      
      //Write to file
      try {
         out.write(contents);
         out.flush();
      } catch (Exception e) {
         throw new IOException("Unexpected error", e);
      } finally {
         out.close();
      }
      
   }//End saveToFile()


  /**
   * read key parameters from a file and generate the private key
   */
  public static PrivateKey readPrivKeyFromFile(String keyFileName) throws IOException 
  {

    InputStream in = 
        Sender.class.getResourceAsStream(keyFileName);
    ObjectInputStream oin =
        new ObjectInputStream(new BufferedInputStream(in));

    try {
      BigInteger m = (BigInteger) oin.readObject();
      BigInteger e = (BigInteger) oin.readObject();

      RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(m, e);
      KeyFactory factory = KeyFactory.getInstance("RSA");
      PrivateKey key = factory.generatePrivate(keySpec);

      return key;
    } catch (Exception e) {
      throw new RuntimeException("Spurious serialisation error", e);
    } finally {
      oin.close();
    }
  }//End readPrivKeyFromFile()


  /**
   * read symmetric key from a file
   */
  public static SecretKeySpec readSymKeyFromFile(String keyFileName) throws IOException 
  {

    InputStream in = 
        Sender.class.getResourceAsStream(keyFileName);
    ObjectInputStream oin =
        new ObjectInputStream(new BufferedInputStream(in));

    try {
      String tempSymKey = oin.readUTF();
      SecretKeySpec symKey = new SecretKeySpec(tempSymKey.getBytes("UTF-8"), "AES");
      return symKey;
    } catch (Exception e) {
      throw new RuntimeException("Spurious serialisation error", e);
    } finally {
      oin.close();
    }
  }//End readSymKeyFromFile()


}//End Sender