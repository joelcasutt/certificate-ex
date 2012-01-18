import java.io.IOException;
import java.io.InputStream;
import java.security.cert.X509Certificate;
import java.util.List;

import org.junit.Test;

public class CertUtilTest {

    InputStream in = null;

    @Test(expected = SortingException.class, timeout=2000)
    public void testBrokenChain() throws IOException, SortingException {
	in = CertUtilTest.class.getResourceAsStream("unsorted_proxy_broken.pem");
	readAndSortChain(in);
    }

    @Test
    public void testChain1() throws IOException, SortingException {
	in = CertUtilTest.class.getResourceAsStream("unsorted_proxy.pem");
	List<X509Certificate> sortedCerts = readAndSortChain(in);
	checkChainOrder(sortedCerts);
    }

    @Test
    public void testChain2() throws IOException, SortingException {
	in = CertUtilTest.class.getResourceAsStream("unsorted_proxy2.pem");
	List<X509Certificate> sortedCerts = readAndSortChain(in);
	checkChainOrder(sortedCerts);
    }

    protected void checkChainOrder(List<X509Certificate> sortedChain) {
	for (int i = 0; i < sortedChain.size() - 1; i++) {
	    if (!sortedChain.get(i).getIssuerX500Principal().equals(sortedChain.get(i + 1).getSubjectX500Principal())) {
		org.junit.Assert.fail("chain is not sorted");
	    }
	}
    }

    protected List<X509Certificate> readAndSortChain(InputStream in) throws IOException, SortingException {
	List<X509Certificate> certArray = null;

	certArray = X509HandlingUtils.readCertificates(in);
	certArray = X509HandlingUtils.sortX509Chain(certArray);

	for (X509Certificate x509Certificate : certArray) {
	    System.out.println(x509Certificate.getSubjectX500Principal().toString());
	    System.out.println(x509Certificate.getIssuerX500Principal().toString());
	}
	System.out.println("");
	return certArray;
    }

}
