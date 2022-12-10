import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.x509.X509V3CertificateGenerator;

import javax.security.auth.x500.X500Principal;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.RSAPublicKeySpec;
import java.util.Date;

/**
 * issuer    证书颁发者
 * subject    证书使用者
 * <p>
 * DN：Distinguish Name
 * 格式：CN=姓名,OU=组织单位名称,O=组织名称,L=城市或区域名称,ST=省/市/自治区名称,C=国家双字母
 */
public class example3_genCrt {
	private static final String KEY_PAIR_ALG = "RSA";
	private static final String SIG_ALG = "SHA256withRSA";
	private static final String DN_ZHANGSAN = "CN=zhangsan,OU=development,O=Huawei,L=ShenZhen,ST=GuangDong,C=CN";
	private static final String DN_CA = "CN=Digicert,OU=Digicert,O=Digicert,L=Linton,ST=Utah,C=US";

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	public static void main(String[] args) throws Exception {
		example3_genCrt cert = new example3_genCrt();
		cert.genRootKeyPair();
		cert.genUserKeyPair();
		cert.genRootCert();
		// cert.genRootCertWithBuilder();
		// cert.genCSR();
		// cert.genCertWithCSR();
		cert.genUserCert();
		cert.verifyRootCert();
		cert.verifyUserCert();
	}

	/**
	 * 生成根证书公钥与私钥对
	 */
	public void genRootKeyPair() throws Exception {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_PAIR_ALG);
		keyPairGenerator.initialize(2048);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		writeObject("./root.public", keyPair.getPublic());
		writeObject("./root.private", keyPair.getPrivate());
	}

	/**
	 * 生成用户证书公钥与私钥对
	 */
	public void genUserKeyPair() throws Exception {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_PAIR_ALG);
		keyPairGenerator.initialize(2048);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		writeObject("./user.public", keyPair.getPublic());
		writeObject("./user.private", keyPair.getPrivate());
	}

	/**
	 * 生成根证书(被BC废弃，但可以使用)
	 */
	public void genRootCert() throws Exception {
		X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
		//设置证书颁发者
		certGen.setIssuerDN(new X500Principal(DN_CA));
		//设置证书有效期
		certGen.setNotAfter(new Date(System.currentTimeMillis() + 100L * 24 * 60 * 60 * 1000));
		certGen.setNotBefore(new Date());
		//设置证书公钥
		certGen.setPublicKey(getRootPublicKey());
		//设置证书序列号
		certGen.setSerialNumber(BigInteger.TEN);
		//设置签名算法
		certGen.setSignatureAlgorithm(SIG_ALG);
		//设置证书使用者
		certGen.setSubjectDN(new X500Principal(DN_CA));
		//使用私钥生成证书，主要是为了进行签名操作
		X509Certificate certificate = certGen.generate(getRootPrivateKey());

		writeFile("./root.cer", certificate.getEncoded());
	}

	/**
	 * 生成根证书的另外一种方式
	 */
	public void genRootCertWithBuilder() throws Exception {
		final AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find(SIG_ALG);
		final AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);

		PublicKey publicKey = getRootPublicKey();
		PrivateKey privateKey = getRootPrivateKey();

		X500Name issuer = new X500Name(DN_CA);
		BigInteger serial = BigInteger.TEN;
		Date notBefore = new Date();
		Date notAfter = new Date(System.currentTimeMillis() + 100L * 24 * 60 * 60 * 1000);
		X500Name subject = new X500Name(DN_CA);

		AlgorithmIdentifier algId = AlgorithmIdentifier.getInstance(sigAlgId);
		AsymmetricKeyParameter publicKeyParameter = PublicKeyFactory.createKey(publicKey.getEncoded());
		SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(publicKeyParameter);
		//此种方式不行，生成证书不完整
		//SubjectPublicKeyInfo publicKeyInfo = new SubjectPublicKeyInfo(algId, publicKey.getEncoded());
		X509v3CertificateBuilder x509v3CertificateBuilder = new X509v3CertificateBuilder(issuer, serial, notBefore, notAfter, subject, publicKeyInfo);

		BcRSAContentSignerBuilder contentSignerBuilder = new BcRSAContentSignerBuilder(sigAlgId, digAlgId);
		AsymmetricKeyParameter privateKeyParameter = PrivateKeyFactory.createKey(privateKey.getEncoded());
		ContentSigner contentSigner = contentSignerBuilder.build(privateKeyParameter);

		X509CertificateHolder certificateHolder = x509v3CertificateBuilder.build(contentSigner);
		org.bouncycastle.asn1.x509.Certificate certificate = certificateHolder.toASN1Structure();
		writeFile("./root.cer", certificate.getEncoded());
	}

	/**
	 * 生成用户证书
	 */
	public void genUserCert() throws Exception {
		X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
		certGen.setIssuerDN(new X500Principal(DN_CA));
		certGen.setNotAfter(new Date(System.currentTimeMillis() + 100L * 24 * 60 * 60 * 1000));
		certGen.setNotBefore(new Date());
		certGen.setPublicKey(getUserPublicKey());
		certGen.setSerialNumber(BigInteger.TEN);
		certGen.setSignatureAlgorithm(SIG_ALG);
		certGen.setSubjectDN(new X500Principal(DN_ZHANGSAN));
		X509Certificate certificate = certGen.generate(getRootPrivateKey());

		writeFile("./user.cer", certificate.getEncoded());
	}

	/**
	 * 验证根证书签名
	 */
	public void verifyRootCert() throws Exception {
		CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
		FileInputStream inStream = new FileInputStream("./root.cer");
		X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(inStream);
		// System.out.println(certificate);
		Signature signature = Signature.getInstance(certificate.getSigAlgName());
		signature.initVerify(certificate);
		signature.update(certificate.getTBSCertificate());
		boolean legal = signature.verify(certificate.getSignature());
		System.out.println(legal);
	}

	/**
	 * 验证用户证书签名
	 */
	public void verifyUserCert() throws Exception {
		CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
		FileInputStream inStream = new FileInputStream("./user.cer");
		X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(inStream);
		// System.out.println(certificate.getPublicKey());
		Signature signature = Signature.getInstance(certificate.getSigAlgName());
		signature.initVerify(getRootPublicKey());
		signature.update(certificate.getTBSCertificate());
		boolean legal = signature.verify(certificate.getSignature());
		System.out.println(legal);
	}

	/**
	 * 生成证书请求文件
	 */
	public void genCSR() throws Exception {
		X500Name subject = new X500Name(DN_ZHANGSAN);
		AsymmetricKeyParameter keyParameter = PrivateKeyFactory.createKey(getUserPrivateKey().getEncoded());
		SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(keyParameter);
		PKCS10CertificationRequestBuilder certificationRequestBuilder = new PKCS10CertificationRequestBuilder(subject, publicKeyInfo);
		final AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find(SIG_ALG);
		final AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);
		BcRSAContentSignerBuilder contentSignerBuilder = new BcRSAContentSignerBuilder(sigAlgId, digAlgId);
		PKCS10CertificationRequest certificationRequest = certificationRequestBuilder.build(contentSignerBuilder.build(keyParameter));
		System.out.println(certificationRequest);
		writeFile("./user.csr", certificationRequest.getEncoded());
	}

	/**
	 * 根据证书请求文件生成用户证书，其实主要是使用根证书私钥为其签名
	 */
	public void genCertWithCSR() throws Exception {
		byte[] encoded = readFile("./user.csr");
		PKCS10CertificationRequest certificationRequest = new PKCS10CertificationRequest(encoded);

		RSAKeyParameters parameter = (RSAKeyParameters) PublicKeyFactory.createKey(certificationRequest.getSubjectPublicKeyInfo());
		RSAPublicKeySpec keySpec = new RSAPublicKeySpec(parameter.getModulus(), parameter.getExponent());
		PublicKey publicKey = KeyFactory.getInstance(KEY_PAIR_ALG).generatePublic(keySpec);
		System.out.println(certificationRequest.getSubject());
		X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
		certGen.setIssuerDN(new X500Principal(DN_CA));
		certGen.setNotAfter(new Date(System.currentTimeMillis() + 100L * 24 * 60 * 60 * 1000));
		certGen.setNotBefore(new Date());

		certGen.setPublicKey(publicKey);
		certGen.setSerialNumber(BigInteger.TEN);
		certGen.setSignatureAlgorithm(SIG_ALG);
		certGen.setSubjectDN(new X500Principal(certificationRequest.getSubject().toString()));
		X509Certificate certificate = certGen.generate(getRootPrivateKey());

		writeFile("./user.cer", certificate.getEncoded());
	}

	public PrivateKey getRootPrivateKey() throws Exception {
		return (PrivateKey) readKey("./root.private");
	}

	public PublicKey getRootPublicKey() throws Exception {
		return (PublicKey) readKey("./root.public");
	}

	public PrivateKey getUserPrivateKey() throws Exception {
		return (PrivateKey) readKey("./user.private");
	}

	public PublicKey getUserPublicKey() throws Exception {
		return (PublicKey) readKey("./user.public");
	}

	public byte[] readFile(String path) throws Exception {
		FileInputStream cntInput = new FileInputStream(path);
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		int b;
		while ((b = cntInput.read()) != -1) {
			baos.write(b);
		}
		cntInput.close();
		byte[] contents = baos.toByteArray();
		baos.close();
		return contents;
	}

	public Key readKey(String path) throws Exception {
		ObjectInputStream ois = new ObjectInputStream(new FileInputStream(path));
		Key key = (Key) ois.readObject();
		ois.close();
		return key;
	}

	public void writeFile(String path, byte[] content) throws Exception {
		FileOutputStream fos = new FileOutputStream(path);
		fos.write(content);
		fos.close();
	}

	public void writeObject(String path, Object object) throws Exception {
		ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(path));
		oos.writeObject(object);
		oos.close();
	}
}