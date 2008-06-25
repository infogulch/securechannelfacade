package org.rev6.scf;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

public class ScpFacadeTest 
{
  
  public static void main(String[] args) 
  {
    /*
     * This is not a junit test... that'll come later.  Maybe.
     */
	  
	String host = args[0];
    String username = args[1];
    String password = args[2];
    //File privateKeyFile = new File(args[3]);
    File sendfile1 = new File(args[4]);
    File sendfile2 = new File(args[4]);
    
    try
    {
      ScpFacade scp = new ScpFacade(host,username,password);
      List<ScpFile> filelist = new ArrayList<ScpFile>();
      filelist.add(new ScpFile(sendfile1,"file1"));
      filelist.add(new ScpFile(sendfile2,"file2"));
      scp.sendFiles(filelist);
    }
    catch (ScpException e)
    {
    	e.printStackTrace();
    }
  }

}
