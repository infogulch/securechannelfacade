package org.rev6.scf;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Collections;
import java.util.List;
import java.util.Properties;

import com.jcraft.jsch.ChannelExec;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.JSchException;
import com.jcraft.jsch.Session;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * @author whaley
 * 
 * ScpFacade is a wrapper around the Java Secure Channel, or JSch library 
 * (http://www.jcraft.com/jsch/) for sending files to a remote server via scp.
 * Only sending files locally to a remote server is supported. Files cannot, 
 * as of this version, be copied from remote servers to a local file. 
 * 
 * It works with username/password authentication or ssh2 username/private key
 * authentication.
 * 
 * The default port of 22 is always used unless explicitly set via the setPort
 * method.
 */
public class ScpFacade
{
  
  private static final String SCP_UPLOAD_COMMAND = "scp -p -t ";
  private static final Properties SCP_PROPERTIES = new Properties();
  static
  {
    SCP_PROPERTIES.put("StrictHostKeyChecking", "No");
  }
  
  protected final Log logger = LogFactory.getLog(this.getClass());
  String host;
  int port = 22;
  String username;
  String password;
  File privateKeyFile;
  boolean usePrivateKey = false;
  
  /**
   * Default constructor. Requires that, at least setUsername, setHost, and 
   * either setPassword or setPrivateKeyFile and usePrivateKey be called. 
   */
  public ScpFacade()
  {
    
  }
  
  /**
   * Requires that setPassword or setPrivateKeyFile and usePrivateKey be called. 
   */
  public ScpFacade(String host, String username)
  {
    this.setHost(host);
    this.setUsername(username);
  }
  
  /**
   * Initializes an ScpFacade to use password based authentication.  sendFile
   * can be directly called after using this constructor.
   */
  public ScpFacade(String host, String username, String password)
  {
    this.setHost(host);
    this.setUsername(username);
    this.setPassword(password);
  }
  
  /**
   * Initializes an ScpFacade to use private key authentication.  sendFile
   * can be directly called after using this constructor.
   */
  public ScpFacade(String host, String username, File privateKeyFile)
  {
    this.setHost(host);
    this.setUsername(username);
    this.setPrivateKeyFile(privateKeyFile);
    this.setUsePrivateKey(true);
  }
  
  /**
   * Checks the input stream from the ssh session for status codes.
   * 
   * @param in
   * @return
   * @throws IOException
   */
  private int checkAck(InputStream in) throws IOException
  {
    int b = in.read();
    
    // b may be
    // 0 for success,
    // 1 for error,
    // 2 for fatal error,
    
    if (b == 0)
      return b;
    if (b == -1)
      return b;
    
    if (b == 1 || b == 2)
    {
      StringBuffer sb = new StringBuffer();
      int c;
      
      do
      {
        c = in.read();
        sb.append((char) c);
      }
      while (c != '\n');
      
      if (b == 1)
      {
        // error
        logger.error("scp failed with an error - reason: " + sb.toString());
      }
      if (b == 2)
      {
        // fatal error
        logger
            .error("scp failed with a fatal error - reason: " + sb.toString());
      }
    }
    return b;
  }
  
  private Session getJSchSession() throws JSchException
  {
    JSch jsch = new JSch();
    
    if (this.usePrivateKey)
      jsch.addIdentity(this.privateKeyFile.getAbsolutePath());
    
    Session session = jsch.getSession(this.username, this.host, this.port);
    session.setConfig(SCP_PROPERTIES);
    
    if (!this.usePrivateKey && this.password != null)
      session.setPassword(this.password);
    
    return session;
  }
  
  
  private void scpFileThroughSshSession(ScpFile scpfile, Session sshSession) 
  {
    logger.info("Attempting to scp file TO " +  this.username + "@" +this.host
        + ":" + scpfile.getPath() + " with a file size of " + 
        Long.toString(scpfile.getFileSize()) + " bytes");
    
    InputStream in = null;
    OutputStream out = null;
    InputStream fileStream = null;
    ChannelExec channel = null;

    
    try
    {
      try
      {
        long startTime = System.currentTimeMillis();
        
        /*
         * Establish a channel on the ssh session for scp'ing
         */
        final String cmd = SCP_UPLOAD_COMMAND + scpfile.getPath();
        channel = (ChannelExec) sshSession.openChannel("exec");
        channel.setCommand(cmd);
        channel.connect();
        
        /*
         * Get io streams for the channel being used and an input stream 
         * for the file being transferred
         */
        fileStream = new FileInputStream(scpfile.getFile());
        in = channel.getInputStream();
        out = channel.getOutputStream();

        /*
         * Check server acknowledgement of the channel
         */
        if (checkAck(in) != 0)
        {
          throw new ScpException(
              "Scp upload to "
                  + this.host
                  + "failed.  Reason: Initializing session returned a status "
                  + "code other than 0");
        }
        
        /*
         * Send the file's size and file name before sending the file.
         */
        String command = "C0644 " + Long.toString(scpfile.getFileSize()) + " " 
          + scpfile.getPath() + "\n";
        out.write(command.getBytes());
        out.flush();
        
        if (checkAck(in) != 0)
        {
          throw new ScpException("Scp upload to " + this.host + " failed.  "
              + "Reason: sending filesize and filename returned a status code "
              + "other than 0");
        }
        
        /*
         * Send the file contents over.
         */
        byte[] buf = new byte[1024];
        while (true)
        {
          int len = fileStream.read(buf, 0, buf.length);
          if (len <= 0)
            break;
          else
            out.write(buf, 0, len);
        }
        
        /*
         * Send 0 to indicate the end of the file
         */
        buf[0] = 0;
        out.write(buf, 0, 1);
        out.flush();
        
        if (checkAck(in) != 0)
        {
          throw new ScpException("Scp upload to " + host + " failed.  Reason: "
              + "sending the file payload resulted a status code other than 0");
        }
        
        long timeInSeconds = (System.currentTimeMillis() - startTime) / 1000;
        logger.info("SUCCESS: scp file TO " + this.host + ":" + scpfile.getPath()
            + " completed in " + Long.toString(timeInSeconds) + "seconds");
          
      }
      finally
      {
        if (out != null)
          out.close();
        if (in != null)
          in.close();
        if (fileStream != null)
          fileStream.close();
        if (channel != null)
          channel.disconnect();
      }
    }
    catch (Exception e)
    {
      logger.error(e.getMessage());
    }
    
    
  }
  
  /**
   * 
   * @param fileContents
   *          The payload to be sent
   * @param filePath
   *          The path + filename of the file being sent.
   * @param filessize
   *          The number of bytes  of the file being sent
   */
  public void sendFiles(List<ScpFile> filelist) throws ScpException
  { 
    Session sshSession = null;
    try
    {
      try
      {
        validateMembers();

        sshSession = getJSchSession();
        sshSession.connect();
        
        for (ScpFile scpFile : filelist)
        {
          scpFileThroughSshSession(scpFile,sshSession);
        }
      }
      finally
      {
        if (sshSession != null)
          sshSession.disconnect();
      }
    }
    catch (Exception e)
    {
      throw new ScpException(e);
    }
  }
  

  public void sendFile(final File file, final String filepath) 
  throws ScpException
  {  
    List<ScpFile> scpFileList = 
      Collections.singletonList(new ScpFile(file,filepath));
    sendFiles(scpFileList);  
  }
  

  /**
   * @param host
   *          The host a file is being copied to.
   */
  public void setHost(String host)
  {
    this.host = host;
  }
  
  /**
   * @param password
   *          The password that will be used in ssh authentication.
   */
  public void setPassword(String password)
  {
    this.password = password;
  }
  
  /**
   * @param port
   *          Sets the ssh port. Default is 22.
   */
  public void setPort(int port)
  {
    this.port = port;
  }
  
  /**
   * 
   * @param privateKeyFileName
   */
  public void setPrivateKeyFile(String privateKeyFileName)
  {
    this.setPrivateKeyFile(new File(privateKeyFileName));
  }
  
  /**
   * 
   * @param privateKeyFile
   */
  public void setPrivateKeyFile(File privateKeyFile)
  {
    this.privateKeyFile = privateKeyFile;
  }
  
  /**
   * Determines whether a private key is used or not when
   * authenticating. Default is false.
   * @param usePrivateKey
   */
  public void setUsePrivateKey(boolean usePrivateKey)
  {
    this.usePrivateKey = usePrivateKey;
  }
  
  /**
   * @param username
   *          The username that will be used in ssh authentication.
   */
  public void setUsername(String username)
  {
    this.username = username;
  }
  
  private void validateMembers() throws ScpException
  {
    if (this.host == null)
      throw new ScpException("host not set.  "
          + "setHost must be called before calling sendFile");
    if (this.username == null)
      throw new ScpException("username not set. "
          + "setUsername must be called before calling sendFile");
    if (this.usePrivateKey)
    {
      if (this.privateKeyFile == null || !this.privateKeyFile.canRead())
        throw new ScpException("if usePrivateKey is true, then a readable "
            + "privateKeyFile must be specified.");
    }
    else
    {
      if (this.password == null)
        throw new ScpException("password not set.  " + "setPassword must be "
            + "called before calling sendFile");
    }
  }
}
