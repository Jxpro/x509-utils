import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

public class X509UtilTest {
	public static void main(String[] args) throws Exception {
		X509Util.printProviders();

		// 自定义RSA公钥
		PublicKey genPublic = X509Util.customRSAPublicKey("24868767854896092588786687407303686877773690333894080011495029830940309475198567361970464647890033375055631051642529002149924877185208899281385878129292186185663539529840044840486029367534836233880978521289120012975984751300675739372426145169450457401456744048334655400383404984013988838597751579412284019508476089195916626638069697313070046637646867604604740726032555131935812336403354554855906457653369726238938995882912391517969859021398013180784463551350234466530008007031446991135485103138878091303677685495071868293487620787584772055998565035817582108636071393569141751372185211443433829520886484151275155702087", "65537");
		// 生成subjectDN
		ObjectDN subjectDN = X509Util.generateDN(
				"jokerxin",
				"HNU",
				"CS",
				"CN",
				"海南",
				"email@example.com",
				"https://www.example.com/license");
		// 生成CRLs序列号数组
		BigInteger[] CRLs = new BigInteger[] { BigInteger.valueOf(2), BigInteger.valueOf(3) };

		// 生成CA root证书
		X509Certificate rootCert = X509Util.generateRootCert(3);
		X509Util.saveEncodedFile("root.cer", rootCert.getEncoded());
		//将CA root证书保存为pem格式
		X509Util.saveEncodedFile("root.pem", X509Util.X509CertificateToPem(rootCert).getBytes(StandardCharsets.UTF_8));
		//生成用户证书
		X509Util.saveEncodedFile("user.cer", X509Util.generateUserCert(3, subjectDN, genPublic).getEncoded());
		//生成CRLs证书
		X509Util.saveEncodedFile("test.crl", X509Util.generateCRLsCert(X509Util.readPrivateKey("root.privateKey","RSA"), CRLs).getEncoded());

		// 校验root证书
		String certPath = "root.cer";
		System.out.println("根CA证书指纹：" + X509Util.getFingerPrint(certPath));
		System.out.println("根CA证书是否有效：" + X509Util.verifyCert(certPath));

		// 校验user证书
		certPath = "user.cer";
		System.out.println("用户证书指纹：" + X509Util.getFingerPrint(certPath));
		System.out.println("用户证书是否有效：" + X509Util.verifyCert(certPath, X509Util.readX509Cert("root.cer").getPublicKey()));
	}
}
