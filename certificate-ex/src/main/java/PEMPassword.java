import java.io.Console;

import org.bouncycastle.openssl.PasswordFinder;


public class PEMPassword implements PasswordFinder {

    public char[] getPassword() {
	Console con = System.console();
	char[] password = con.readPassword();
	return password;
    }

}
