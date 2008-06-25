package org.rev6.scf;

public class ScpException extends Exception
{
  static final long serialVersionUID = 1L;
  public ScpException(String message){super(message);}
  public ScpException(Throwable cause){super(cause);}
  public ScpException(String message, Throwable cause){super(message, cause);}
}
