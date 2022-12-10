import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.x509.X509V3CertificateGenerator;

import javax.security.auth.x500.X500Principal;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Date;

public class X509Util {
	private static final int KEY_SIZE = 2048;
	private static final String KEY_ALG = "RSA";
	private static final String SIG_ALG = "SHA256withRSA";

	private static final String CRL_URL = "https://www.example.com/crl";
	private static final String ROOT_DN = "CN=SelfSign Root CA,O=HNU,OU=CS,C=CN,ST=海南省";
	private static final DistributionPoint[] distributionPoints = new DistributionPoint[1];
	private static final Date NotBefore = new Date(System.currentTimeMillis() - 1000L * 60 * 60 * 24);
	private static final Date NotAfter = new Date(System.currentTimeMillis() + 1000L * 60 * 60 * 24 * 365 * 10);

	static {
		// 添加BouncyCastle支持
		Security.addProvider(new BouncyCastleProvider());
		// 构造CRL distribution points扩展值
		GeneralName generalName = new GeneralName(GeneralName.uniformResourceIdentifier, CRL_URL);
		DistributionPointName distributionPointName = new DistributionPointName(new GeneralNames(generalName));
		distributionPoints[0] = new DistributionPoint(distributionPointName, null, null);
	}

	/**
	 * 打印所有provider的名称和信息
	 */
	public static void printProviders() {
		for (Provider p : Security.getProviders()) {
			System.out.println(p.getName());
			System.out.println(p.getInfo());
		}
	}


	/**
	 * 生成RSA密钥对
	 *
	 * @return keyPair 密钥对
	 */
	public static KeyPair generateKeyPair() throws Exception {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALG);
		keyPairGenerator.initialize(KEY_SIZE);
		return keyPairGenerator.generateKeyPair();
	}


	/**
	 * 根据n和d生成RSA公钥
	 *
	 * @param n 模数n
	 * @param e 公钥e，一般为65537
	 * @return publicKey 公钥
	 */
	public static PublicKey customRSAPublicKey(String n, String e) throws Exception {
		// 构造RSA公钥参数RSAPublicKeySpec
		RSAPublicKeySpec spec = new RSAPublicKeySpec(new BigInteger(n), new BigInteger(e));
		// 使用RSAPublicKeySpec构造RSA公钥
		return KeyFactory.getInstance(KEY_ALG).generatePublic(spec);
	}


	/**
	 * 生成一个DN对象
	 *
	 * @param commonName         通用名称
	 * @param organization       组织名称
	 * @param organizationalUnit 组织单位名称
	 * @param countryName        国家名称
	 * @param provinceName       省份名称
	 * @param email              邮箱
	 * @param licenseUrl         营业执照/许可证 URL
	 * @return ObjectDN对象
	 */
	public static ObjectDN generateDN(
			String commonName,
			String organization,
			String organizationalUnit,
			String countryName,
			String provinceName,
			String email,
			String licenseUrl) {
		ObjectDN objectDN = new ObjectDN();
		objectDN.setCommonName(commonName);
		objectDN.setOrganization(organization);
		objectDN.setOrganizationalUnit(organizationalUnit);
		objectDN.setCountryName(countryName);
		objectDN.setProvinceName(provinceName);
		objectDN.setEmail(email);
		objectDN.setLicenseUrl(licenseUrl);
		return objectDN;
	}


	/**
	 * 生成根CA数字证书
	 *
	 * @param api 证书生成API
	 *            1：使用X509V3CertificateGenerator
	 *            2：使用X509v3CertificateBuilder
	 *            3：使用JcaX509v3CertificateBuilder
	 *            需要注意的是：
	 *            方法1和3生成的CA证书都可以验证通过方法1和3生成的用户证书，因为其DN均使用的是X500Principal
	 *            方法2生成的CA证书只能验证同样通过方法2生成的证书，因为其DN使用的是X500Name
	 *            因为X500Principal和X500Name(X509Name)在处理CN,OU,等字段时的顺序上不一致，会导致验证失败
	 * @return X509Certificate证书
	 */
	public static X509Certificate generateRootCert(int api) throws Exception {
		// 生成RSA密钥对
		KeyPair keyPair = generateKeyPair();
		// 保存私钥
		saveEncodedFile("root.privateKey", keyPair.getPrivate().getEncoded());
		// 生成证书
		X509Certificate certificate;
		switch (api) {
			case 1:
				certificate = genRootWithX509V3CertificateGenerator(keyPair.getPublic(), keyPair.getPrivate());
				break;
			case 2:
				certificate = genRootWithX509v3CertificateBuilder(keyPair.getPublic(), keyPair.getPrivate());
				break;
			case 3:
				certificate = genRootWithJcaX509v3CertificateBuilder(keyPair.getPublic(), keyPair.getPrivate());
				break;
			default:
				throw new IllegalArgumentException("Invalid API");
		}
		return certificate;
	}


	/**
	 * 使用X509V3CertificateGenerator生成根CA数字证书
	 *
	 * @param publicKey  公钥
	 * @param privateKey 私钥
	 * @return X509Certificate证书
	 */
	public static X509Certificate genRootWithX509V3CertificateGenerator(PublicKey publicKey, PrivateKey privateKey) throws Exception {
		// 证书构造器
		X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
		// 设置颁发者DN
		certGen.setIssuerDN(new X500Principal(ROOT_DN));
		// 设置序列号
		certGen.setSerialNumber(BigInteger.ONE);
		// 设置有效期
		certGen.setNotBefore(NotBefore);
		certGen.setNotAfter(NotAfter);
		// 设置使用者DN
		certGen.setSubjectDN(new X500Principal(ROOT_DN));
		// 设置公钥
		certGen.setPublicKey(publicKey);
		// 设置签名算法
		certGen.setSignatureAlgorithm(SIG_ALG);
		// 设置扩展信息
		certGen.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
		certGen.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
		certGen.addExtension(Extension.cRLDistributionPoints, false, new CRLDistPoint(distributionPoints));
		// 生成证书
		return certGen.generate(privateKey, "BC");
	}


	/**
	 * 使用X509v3CertificateBuilder生成根CA数字证书
	 * 该方法生成的CA证书只能验证同样通过这个方法生成的证书，因为其DN使用的是X500Name,而不是X500Principal
	 *
	 * @param publicKey  公钥
	 * @param privateKey 私钥
	 * @return X509Certificate证书
	 */
	public static X509Certificate genRootWithX509v3CertificateBuilder(PublicKey publicKey, PrivateKey privateKey) throws Exception {
		// 组装公钥信息
		AsymmetricKeyParameter publicKeyParameter = PublicKeyFactory.createKey(publicKey.getEncoded());
		SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(publicKeyParameter);
		// 证书构造器
		X509v3CertificateBuilder certGen = new X509v3CertificateBuilder(
				new X500Name(ROOT_DN),
				BigInteger.ONE,
				NotBefore,
				NotAfter,
				new X500Name(ROOT_DN),
				publicKeyInfo)
				.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign))
				.addExtension(Extension.basicConstraints, true, new BasicConstraints(true))
				.addExtension(Extension.cRLDistributionPoints, false, new CRLDistPoint(distributionPoints));
		// 签名构造器
		ContentSigner sigGen = new JcaContentSignerBuilder(SIG_ALG).setProvider("BC").build(privateKey);
		// 生成证书
		return new JcaX509CertificateConverter().setProvider("BC").getCertificate(certGen.build(sigGen));
	}


	/**
	 * 使用JcaX509v3CertificateBuilder生成根CA数字证书
	 *
	 * @param publicKey  公钥
	 * @param privateKey 私钥
	 * @return X509Certificate证书
	 */
	public static X509Certificate genRootWithJcaX509v3CertificateBuilder(PublicKey publicKey, PrivateKey privateKey) throws Exception {
		// 证书构造器
		X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(
				new X500Principal(ROOT_DN),
				BigInteger.ONE,
				NotBefore,
				NotAfter,
				new X500Principal(ROOT_DN),
				publicKey)
				.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign))
				.addExtension(Extension.basicConstraints, true, new BasicConstraints(true))
				.addExtension(Extension.cRLDistributionPoints, false, new CRLDistPoint(distributionPoints));
		// 签名构造器
		ContentSigner sigGen = new JcaContentSignerBuilder(SIG_ALG).setProvider("BC").build(privateKey);
		// 生成证书
		return new JcaX509CertificateConverter().setProvider("BC").getCertificate(certGen.build(sigGen));
	}


	/**
	 * 生成用户数字证书
	 *
	 * @param api       证书生成API
	 *                  1：使用X509V3CertificateGenerator
	 *                  2：使用X509v3CertificateBuilder
	 *                  3：使用JcaX509v3CertificateBuilder
	 *                  需要注意的是：
	 *                  方法1和3生成的CA证书都可以验证通过方法1和3生成的用户证书，因为其DN均使用的是X500Principal
	 *                  方法2生成的CA证书只能验证同样通过方法2生成的证书，因为其DN使用的是X500Name
	 *                  因为X500Principal和X500Name(X509Name)在处理CN,OU,等字段时的顺序上不一致，会导致验证失败
	 * @param subjectDN 使用者DN
	 * @param publicKey 用户自定义公钥
	 * @return X509Certificate证书
	 */
	public static X509Certificate generateUserCert(int api, ObjectDN subjectDN, PublicKey publicKey) throws Exception {
		// 读取CA私钥
		PrivateKey privateKey = readPrivateKey("root.privateKey", KEY_ALG);
		// 生成证书
		X509Certificate certificate;
		switch (api) {
			case 1:
				certificate = genUserWithX509V3CertificateGenerator(subjectDN, publicKey, privateKey);
				break;
			case 2:
				certificate = genUserWithX509v3CertificateBuilder(subjectDN, publicKey, privateKey);
				break;
			case 3:
				certificate = genUserWithJcaX509v3CertificateBuilder(subjectDN, publicKey, privateKey);
				break;
			default:
				throw new IllegalArgumentException("Invalid API");
		}
		return certificate;
	}


	/**
	 * 使用X509V3CertificateGenerator生成用户数字证书
	 *
	 * @param subjectDN  使用者DN
	 * @param publicKey  用户自定义公钥
	 * @param privateKey CA私钥
	 * @return X509Certificate证书
	 */
	public static X509Certificate genUserWithX509V3CertificateGenerator(ObjectDN subjectDN, PublicKey publicKey, PrivateKey privateKey) throws Exception {
		// 证书构造器
		X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
		// 设置颁发者DN
		certGen.setIssuerDN(new X500Principal(ROOT_DN));
		// 设置序列号
		certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
		// 设置有效期
		certGen.setNotBefore(NotBefore);
		certGen.setNotAfter(NotAfter);
		// 设置使用者DN
		certGen.setSubjectDN(subjectDN.getX500Principal());
		// 设置公钥
		certGen.setPublicKey(publicKey);
		// 设置签名算法
		certGen.setSignatureAlgorithm(SIG_ALG);
		// 设置扩展信息
		certGen.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
		certGen.addExtension(Extension.basicConstraints, false, new BasicConstraints(true));
		certGen.addExtension(Extension.cRLDistributionPoints, false, new CRLDistPoint(distributionPoints));
		certGen.addExtension(Extension.subjectAlternativeName, false, subjectDN.getSubjectAlternativeNames());
		// 生成证书
		return certGen.generate(privateKey, "BC");
	}


	/**
	 * 使用X509v3CertificateBuilder生成用户数字证书
	 * 该方法生成的用户证书只能由同样通过这个方法生成的证书来验证，因为其DN使用的是X500Name,而不是X500Principal
	 *
	 * @param subjectDN  使用者DN
	 * @param publicKey  用户自定义公钥
	 * @param privateKey CA私钥
	 * @return X509Certificate证书
	 */
	public static X509Certificate genUserWithX509v3CertificateBuilder(ObjectDN subjectDN, PublicKey publicKey, PrivateKey privateKey) throws Exception {
		// 组装公钥信息
		AsymmetricKeyParameter publicKeyParameter = PublicKeyFactory.createKey(publicKey.getEncoded());
		SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(publicKeyParameter);
		// 证书构造器
		X509v3CertificateBuilder certGen = new X509v3CertificateBuilder(
				new X500Name(ROOT_DN),
				BigInteger.valueOf(System.currentTimeMillis()),
				NotBefore,
				NotAfter,
				subjectDN.getX500Name(),
				publicKeyInfo)
				.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature))
				.addExtension(Extension.basicConstraints, false, new BasicConstraints(true))
				.addExtension(Extension.cRLDistributionPoints, false, new CRLDistPoint(distributionPoints))
				.addExtension(Extension.subjectAlternativeName, false, subjectDN.getSubjectAlternativeNames());
		// 签名构造器
		ContentSigner sigGen = new JcaContentSignerBuilder(SIG_ALG).setProvider("BC").build(privateKey);
		// 生成证书
		return new JcaX509CertificateConverter().setProvider("BC").getCertificate(certGen.build(sigGen));
	}


	/**
	 * 使用JcaX509v3CertificateBuilder生成用户数字证书
	 *
	 * @param subjectDN  使用者DN
	 * @param publicKey  用户自定义公钥
	 * @param privateKey CA私钥
	 * @return X509Certificate证书
	 */
	public static X509Certificate genUserWithJcaX509v3CertificateBuilder(ObjectDN subjectDN, PublicKey publicKey, PrivateKey privateKey) throws Exception {
		// 证书构造器
		X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(
				new X500Principal(ROOT_DN),
				BigInteger.valueOf(System.currentTimeMillis()),
				NotBefore,
				NotAfter,
				subjectDN.getX500Principal(),
				publicKey)
				.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature))
				.addExtension(Extension.basicConstraints, false, new BasicConstraints(true))
				.addExtension(Extension.cRLDistributionPoints, false, new CRLDistPoint(distributionPoints))
				.addExtension(Extension.subjectAlternativeName, false, subjectDN.getSubjectAlternativeNames());
		// 签名构造器
		ContentSigner sigGen = new JcaContentSignerBuilder(SIG_ALG).setProvider("BC").build(privateKey);
		// 生成证书
		return new JcaX509CertificateConverter().setProvider("BC").getCertificate(certGen.build(sigGen));
	}


	/**
	 * 将certificate转换为PEM格式
	 *
	 * @param certificate 证书
	 * @return PEM格式证书
	 */
	public static String X509CertificateToPem(X509Certificate certificate) throws Exception {
		StringWriter sw = new StringWriter();
		JcaPEMWriter pemWriter = new JcaPEMWriter(sw);
		pemWriter.writeObject(certificate);
		pemWriter.close();
		return sw.toString();
	}


	/**
	 * 生成CRL证书吊销列表
	 *
	 * @param caPrivateKey CA私钥
	 * @param serials      吊销的证书序列号
	 * @return X509CRL证书吊销列表
	 */
	public static X509CRL generateCRLsCert(PrivateKey caPrivateKey, BigInteger[] serials) throws Exception {
		// 证书吊销列表构造器
		JcaX509v2CRLBuilder crlGen = new JcaX509v2CRLBuilder(new X500Principal(ROOT_DN), new Date());
		// 设置下次更新时间
		crlGen.setNextUpdate(new Date(System.currentTimeMillis() + 1000L * 60 * 60 * 24));
		// 设置吊销证书序列号
		for (BigInteger serial : serials) {
			crlGen.addCRLEntry(serial, new Date(), CRLReason.affiliationChanged);
		}
		// 签名构造器
		ContentSigner sigGen = new JcaContentSignerBuilder(SIG_ALG).setProvider("BC").build(caPrivateKey);
		// 生成证书吊销列表
		return new JcaX509CRLConverter().setProvider("BC").getCRL(crlGen.build(sigGen));
	}


	/**
	 * 计算X509数字证书的指纹
	 *
	 * @param certPath 证书路径
	 * @return 证书指纹
	 */
	public static String getFingerPrint(String certPath) throws Exception {
		X509Certificate cert = readX509Cert(certPath);
		MessageDigest md = MessageDigest.getInstance("sha1");
		byte[] digest = md.digest(cert.getEncoded());
		return new String(Hex.encode(digest));
	}


	/**
	 * 验证根CA数字证书的完整性
	 *
	 * @param certPath 证书路径
	 * @return 验证结果
	 */
	public static boolean verifyCert(String certPath) throws Exception {
		X509Certificate cert = readX509Cert(certPath);
		PublicKey publicKey = cert.getPublicKey();
		cert.checkValidity();
		cert.verify(publicKey);
		return true;
	}


	/**
	 * 验证根CA数字证书的完整性
	 *
	 * @param certPath  证书路径
	 * @param publicKey 公钥
	 * @return 验证结果
	 */
	public static boolean verifyCert(String certPath, PublicKey publicKey) throws Exception {
		X509Certificate cert = readX509Cert(certPath);
		cert.checkValidity();
		cert.verify(publicKey);
		return true;
	}


	/**
	 * 从文件中读取X509证书
	 *
	 * @param certFile 证书文件路径
	 * @return X509Certificate证书
	 */
	public static X509Certificate readX509Cert(String certFile) throws Exception {
		CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
		return (X509Certificate) cf.generateCertificate(new FileInputStream(certFile));
	}


	/**
	 * 从文件中读取私钥
	 *
	 * @param privateKeyPath 私钥文件路径
	 * @param algorithm      签名算法
	 * @return 私钥
	 */
	public static PrivateKey readPrivateKey(String privateKeyPath, String algorithm) throws Exception {
		KeyFactory kf = KeyFactory.getInstance(algorithm, "BC");
		return kf.generatePrivate(new PKCS8EncodedKeySpec(readFile(privateKeyPath)));
	}


	/**
	 * 读取文件
	 *
	 * @param path 文件路径
	 * @return 文件内容
	 */
	public static byte[] readFile(String path) throws Exception {
		FileInputStream fileInputStream = new FileInputStream(path);
		byte[] bytes = new byte[fileInputStream.available()];
		if (fileInputStream.read(bytes) == -1) {
			throw new Exception("文件读取失败");
		}
		return bytes;
	}


	/**
	 * 保存密钥或证书到文件
	 *
	 * @param filePath    文件路径
	 * @param encodedFile 编码后的内容
	 */
	public static void saveEncodedFile(String filePath, byte[] encodedFile) throws IOException {
		FileOutputStream fileOutputStream = new FileOutputStream(filePath);
		fileOutputStream.write(encodedFile);
		fileOutputStream.close();
	}
}