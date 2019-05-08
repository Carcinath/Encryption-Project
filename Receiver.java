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


public class Receiver
{
  private static int BUFFER_SIZE = 32 * 1024;
  
  public static void main(String[] args) throws Exception 
  {
    //read the keys from the files
    PublicKey xPubKey = readPubKeyFromFile("XPublic.key");
    SecretKeySpec symKey = readSymKeyFromFile("symmetric.key");
    
    //Ask for output name of message file
    Scanner input = new Scanner(System.in);
    System.out.println("Input the name of the message file:");
    String msgFileName = input.nextLine();
    
    //decrypt message.aescipher using AES with the symmetric key
    decryptAES("message.aescipher", symKey);
    
    //Decrypt message.ds-msg using RSA encryption with the X public key
    decryptRSA("message.ds-msg", xPubKey, msgFileName);
    
    //SHA256 the message & print
    msgDigest(msgFileName);

  }//End main
  
  
  /**
   * Decrpts the AES encrypted message with AES decryption using the symmetric key
   */
  public static void decryptAES(String cipherFileName, SecretKeySpec symKey) throws Exception 
  {
    InputStream in = new FileInputStream(cipherFileName);
    byte[] cipherContents = new byte[BUFFER_SIZE],
           decryptText = new byte[BUFFER_SIZE];
    int bytesRead = 0;
    boolean firstBlock = true,
            append = true;
    
    Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding", "SunJCE");
    cipher.init(Cipher.DECRYPT_MODE, symKey);
    
    while( (bytesRead = in.read(cipherContents)) != -1 )
    {
      append = true;
      if(firstBlock)
      {
         firstBlock = false;
         append = false;
      }
      
      if(bytesRead == BUFFER_SIZE)
      {
         decryptText = cipher.update(cipherContents);
         saveToFile("message.ds-msg", decryptText, append);
      }
      else //Adjust array before saving to file
      {
         byte[] tempRemains = new byte[bytesRead];
         
         for(int parser = 0; parser < bytesRead; parser++)
            tempRemains[parser] = cipherContents[parser];
         
         decryptText = cipher.doFinal(tempRemains);
         saveToFile("message.ds-msg", decryptText, append);
      }
      
    }//End while - buffer each block
    in.close();
    
  }//End decryptAES()
  
  
  /**
   * Seporating the digital digest (SHA256) and the message, saving the message to 
   * msgFileName and calculating the RSA decryption of the digital digest.
   */
  public static void decryptRSA(String dsFileName, PublicKey xPubKey, 
                                String msgFileName) throws Exception 
  {
    Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
    InputStream in = new FileInputStream(dsFileName);
    
    
    //Decrypt the RSA encrypted hash value
    byte[] dsContents = new byte[128];
    in.read(dsContents);
    in.close();
    
    cipher.init(Cipher.DECRYPT_MODE, xPubKey);
    byte[] hashBytes = cipher.doFinal(dsContents);
    
    
    //Then save the digital digest of the message to a file
    saveToFile("message.dd", hashBytes, false );
    
    
    //Seporate message to from the hash of the message
    seporateMsg(dsFileName, msgFileName);
  }//End decryptRSA()
  
  
  /**
   * Seporates the message from message.ds-msg and puts it into msgFileName
   */
  public static void seporateMsg(String dsMsgFileName, String msgFileName) throws Exception 
  {
    InputStream in = new FileInputStream(dsMsgFileName);
    byte[] MsgContents = new byte[BUFFER_SIZE],
           dsContents = new byte[128];
    int bytesRead = 0;
    boolean firstBlock = true,
            append = true;
    
    in.read(dsContents);
    
    while( (bytesRead = in.read(MsgContents)) != -1 )
    {
      append = true;
      if(firstBlock)
      {
         firstBlock = false;
         append = false;
      }
      
      if(bytesRead == BUFFER_SIZE)
      {
         saveToFile(msgFileName, MsgContents, append);
      }
      else //Adjust array before saving to file
      {
         byte[] tempRemains = new byte[bytesRead];
         
         for(int parser = 0; parser < bytesRead; parser++)
            tempRemains[parser] = MsgContents[parser];
            
         saveToFile(msgFileName, tempRemains, append);
      }
      
    }//End while - buffer each block
    in.close();
    
  }//End seporateMsg()
  
  
  /**
   * Calculating the digital digest (SHA256) of the message file
   */
  public static void msgDigest(String msgFileName) throws Exception 
  {
    //Contents of message.dd
    InputStream hashFile = new FileInputStream("message.dd");
    byte[] hashReceived = new byte[32];
    hashFile.read(hashReceived);
    hashFile.close();
    
    //Calculate the SHA of the message we got
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
    System.out.println("\nDigit digest of the message (hash value) Received:");
    print(hashReceived);
    //Print the hashed message
    System.out.println("Digit digest of the message (hash value) Calculated:");
    print(hash);
    
    
    //Compare the hashes
    boolean hashPassed = true;
    for(int reader = 0; reader < hash.length; reader++)
    {
      if(hash[reader] != hashReceived[reader])
         hashPassed = false;
    }
    
    if(hashPassed)
      System.out.println("\nPassed: The hashes are the same.");
    else
      System.out.println("\nFailed: The hashes are NOT the same!");
    
  }//End msgDigest()
  
  
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
   * read key parameters from a file and generate the public key
   */
  public static PublicKey readPubKeyFromFile(String keyFileName) throws IOException 
  {
    InputStream in = 
        Receiver.class.getResourceAsStream(keyFileName);
    ObjectInputStream oin =
        new ObjectInputStream(new BufferedInputStream(in));
    
    try {
      BigInteger m = (BigInteger) oin.readObject();
      BigInteger e = (BigInteger) oin.readObject();
      
      RSAPublicKeySpec keySpec = new RSAPublicKeySpec(m, e);
      KeyFactory factory = KeyFactory.getInstance("RSA");
      PublicKey key = factory.generatePublic(keySpec);
      
      return key;
    } catch (Exception e) {
      throw new RuntimeException("Spurious serialisation error", e);
    } finally {
      oin.close();
    }
  }//End readPubKeyFromFile()


  /**
   * read symmetric key from a file
   */
  public static SecretKeySpec readSymKeyFromFile(String keyFileName) throws IOException 
  {

    InputStream in = 
        Receiver.class.getResourceAsStream(keyFileName);
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


}//End Receiver