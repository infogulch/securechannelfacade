package org.rev6.scf;

import java.io.File;


public class ScpFile
{
  private final File file;
  private final String path;
  
  public ScpFile(final File file, final String path)
  {
    if (file == null || path == null) throw new 
      IllegalArgumentException("File reference and path must be non-null"); 
    else if (!file.exists())
      throw new IllegalArgumentException("The file reference " + 
          file.getAbsolutePath()+ " must actually be a file that exists.");
    else
    {
      this.file = file;
      this.path = path;
    }
  }
  
  public ScpFile(final File file)
  {
    this(file,file.getName());
  }
  
  public File getFile()
  {
    return this.file;
  }
  
  public String getPath()
  {
    return this.path;
  }
  
  public long getFileSize()
  {
    return this.file.length();
  }
}
