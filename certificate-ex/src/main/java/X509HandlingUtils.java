import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMReader;

public class X509HandlingUtils {

    static {
	/* add BouncyCastle security provider if not already done */
	if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
	    Security.addProvider(new BouncyCastleProvider());
	}
    }

    /**
     * Reads all PEM encoded X.509 certificates from an input stream
     * 
     * @param file
     *            the file to read from
     * @return a list of all X.509 certificates
     * @throws IOException
     *             if an error occurs while reading the file
     */
    public static LinkedList<X509Certificate> readCertificates(InputStream in) throws IOException {
	InputStreamReader inReader = new InputStreamReader(in);
	PEMReader reader = new PEMReader(inReader, new PEMPassword());
	LinkedList<X509Certificate> certs = new LinkedList<X509Certificate>();
	Object object = reader.readObject();
	while (object != null) {
	    try {
		// object is null at EOF
		if (object instanceof X509Certificate) {
		    X509Certificate cert = (X509Certificate) object;
		    certs.add(cert);
		    // System.out.println(cert.getSubjectX500Principal());
		    object = reader.readObject();
		} else {
		    System.out.println("found something that is not a cert: ");
		    if (object != null) {
			System.out.println(object.toString());
		    }
		}
	    } catch (IOException e) {
		System.out.println(e.getMessage());
	    }
	}

	try {
	    reader.close();
	} catch (Exception e) {
	    // ignored
	    System.out.println("error while closing");
	}

	return certs;
    }

    /**
     * sort a list of X509-certificate so they form a valid chain
     * 
     * @param certs
     *            a list containing yet unsorted certificates
     * @return a list of certificates sorted, so they form a valid chain
     * @throws SortingException
     *             if the given tuple of certificates does not contain all
     *             elements to form a valid chain, a SortingException is thrown
     */
    public static List<X509Certificate> sortX509Chain(List<X509Certificate> certs) throws SortingException {

	LinkedList<X509Certificate> sortedCerts = new LinkedList<X509Certificate>();
	LinkedList<X509Certificate> unsortedCerts = new LinkedList<X509Certificate>(certs);
	// take the first argument of the unsorted List, remove it, and set it
	// as the first element of the sorted List
	sortedCerts.add(unsortedCerts.pollFirst());
	int escapeCounter = 0;

	while (!unsortedCerts.isEmpty()) {
	    int initialSize = unsortedCerts.size();
	    // take the next element of the unsorted List, remove it, and test
	    // if it can be added either at the beginning or the end of the
	    // sorted list. If it cannot be added at either side put it back at
	    // the end of the unsorted List. Go ahead until there are no more
	    // elements in the unsorted List
	    X509Certificate currentCert = unsortedCerts.pollFirst();
	    if (currentCert.getIssuerX500Principal().equals(sortedCerts.peekFirst().getSubjectX500Principal())) {
		sortedCerts.offerFirst(currentCert);
	    } else if (currentCert.getSubjectX500Principal().equals(sortedCerts.peekLast().getIssuerX500Principal())) {
		sortedCerts.offerLast(currentCert);
	    } else {
		unsortedCerts.offerLast(currentCert);
	    }

	    // to prevent a endless loop, the following construct escapes the
	    // loop if no change is made after each remaining, yet unsorted,
	    // certificate has been tested twice if it fits the chain
	    if (unsortedCerts.size() == initialSize) {
		escapeCounter++;
		if (escapeCounter >= (2 * initialSize)) {
		    throw new SortingException();
		}
	    } else {
		escapeCounter = 0;
	    }
	}
	return sortedCerts;
    }

}
