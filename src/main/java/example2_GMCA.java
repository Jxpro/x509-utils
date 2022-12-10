import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.encoders.Base64;

import javax.security.auth.x500.X500Principal;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Date;
import java.util.Random;

public class example2_GMCA {
	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	public static void main(String[] args) throws Exception {
		genGMCACert();
		genCertWithCaSign();
		testDigitalSign();
		testSM2EcDc();
	}

	public static void genGMCACert() throws Exception {
		System.out.println("=============测试生成国密CA根证书=============");

		// 生成秘钥对
		KeyPairGenerator g = KeyPairGenerator.getInstance("EC", "BC");
		g.initialize(new ECNamedCurveGenParameterSpec("sm2p256v1"));
		KeyPair p = g.generateKeyPair();
		PrivateKey priKey = p.getPrivate();
		PublicKey pubKey = p.getPublic();

		// 颁发者信息
		X500Principal iss = new X500Principal("CN=test GM ROOT CA,OU=test,C=CN,S=Guangdong,O=test");
		// 构造CRL distribution points扩展值
		GeneralName generalName = new GeneralName(GeneralName.uniformResourceIdentifier, "http://www.test.cn");
		DistributionPointName distributionPointName = new DistributionPointName(new GeneralNames(generalName));
		DistributionPoint[] distributionPoints = new DistributionPoint[]{
				new DistributionPoint(distributionPointName, null, null)
		};
		// 证书使用者的可替代别名
		GeneralName[] subjectAlternativeName = {
				new GeneralName(GeneralName.rfc822Name, "gmca@test.cn"),
				new GeneralName(GeneralName.dNSName, "ca.test.cn")
		};
		// 生成证书builder
		X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(
				iss,
				BigInteger.valueOf(10),
				new Date(System.currentTimeMillis()),
				new Date(System.currentTimeMillis() + 100L * 24 * 60 * 60 * 1000),
				iss,
				pubKey)
				.addExtension(Extension.keyUsage, true,
						new X509KeyUsage(0xfe))
				.addExtension(Extension.extendedKeyUsage, false,
						new DERSequence(KeyPurposeId.anyExtendedKeyUsage))
				.addExtension(Extension.subjectAlternativeName, false,
						new GeneralNames(subjectAlternativeName))
				.addExtension(Extension.cRLDistributionPoints, false,
						new CRLDistPoint(distributionPoints));
		// 构造签名者
		ContentSigner sigGen = new JcaContentSignerBuilder("SM3withSM2").setProvider("BC").build(priKey);

		// 生成证书
		X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certGen.build(sigGen));

		// 验证有效性
		cert.checkValidity(new Date());
		cert.verify(pubKey);

		// ByteArrayInputStream bIn = new ByteArrayInputStream(cert.getEncoded());
		// CertificateFactory fact = CertificateFactory.getInstance("X.509", "BC");
		// cert = (X509Certificate) fact.generateCertificate(bIn);

		saveFile("rootCert.cer", cert.getEncoded());
		saveFile("rootPrivateKey", priKey.getEncoded());
		System.out.println("Root Certificate:" + Base64.toBase64String(cert.getEncoded()));
		System.out.println("Root PrivateKey:" + Base64.toBase64String(priKey.getEncoded()));
		System.out.println("=============测试生成国密CA根证书=============");
	}

	public static void genCertWithCaSign() throws Exception {
		System.out.println("=============测试国密CA根证书签发国密证书=============");

		// 读取CA证书
		CertificateFactory certificateFactory = CertificateFactory.getInstance("X509", "BC");
		Certificate caRootCert = certificateFactory.generateCertificate(new FileInputStream("rootCert.cer"));

		// 读取CA私钥
		KeyFactory keyFactory = KeyFactory.getInstance(caRootCert.getPublicKey().getAlgorithm(), "BC");
		PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(readFile("rootPrivateKey"));
		PrivateKey caPrivateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);

		// 生成秘钥对
		KeyPairGenerator g = KeyPairGenerator.getInstance("EC", "BC");
		g.initialize(new ECNamedCurveGenParameterSpec("sm2p256v1"));
		KeyPair p = g.generateKeyPair();
		PrivateKey priKey = p.getPrivate();
		PublicKey pubKey = p.getPublic();

		// 构造CRL distribution points扩展值
		GeneralName generalName = new GeneralName(GeneralName.uniformResourceIdentifier, "http://www.test.cn");
		DistributionPointName distributionPointName = new DistributionPointName(new GeneralNames(generalName));
		DistributionPoint[] distributionPoints = new DistributionPoint[]{
				new DistributionPoint(distributionPointName, null, null)
		};
		// 证书使用者的可替代别名
		GeneralName[] subjectAlternativeName = {
				new GeneralName(GeneralName.rfc822Name, "gmca@test.cn"),
				new GeneralName(GeneralName.dNSName, "ca.test.cn"),
				// 包含IP地址
				new GeneralName(GeneralName.iPAddress, "192.168.1.1"),
				new GeneralName(GeneralName.uniformResourceIdentifier, "license:https://www.test.cn")
		};
		// 生成证书builder
		X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(
				(X509Certificate) caRootCert,
				BigInteger.valueOf(new Random().nextInt()),
				new Date(System.currentTimeMillis()),
				new Date(System.currentTimeMillis() + 100L * 24 * 60 * 60 * 1000),
				new X500Principal("CN=TestCert"),
				pubKey)
				.addExtension(Extension.keyUsage, true,
						new X509KeyUsage(X509KeyUsage.digitalSignature | X509KeyUsage.nonRepudiation))
				.addExtension(Extension.extendedKeyUsage, false,
						new DERSequence(KeyPurposeId.anyExtendedKeyUsage))
				.addExtension(Extension.subjectAlternativeName, false,
						new GeneralNames(subjectAlternativeName))
				.addExtension(Extension.cRLDistributionPoints, false,
						new CRLDistPoint(distributionPoints));

		// 构造签名者
		ContentSigner sigGen = new JcaContentSignerBuilder("SM3withSM2").setProvider("BC").build(caPrivateKey);

		// 生成证书
		X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certGen.build(sigGen));

		// 验证有效性
		cert.checkValidity(new Date());
		cert.verify(caRootCert.getPublicKey());

		// ByteArrayInputStream bIn = new ByteArrayInputStream(cert.getEncoded());
		// CertificateFactory fact = CertificateFactory.getInstance("X.509", "BC");
		// cert = (X509Certificate) fact.generateCertificate(bIn);

		saveFile("userCert.cer", cert.getEncoded());
		saveFile("userPrivateKey", priKey.getEncoded());
		System.out.println("User Certificate:" + Base64.toBase64String(cert.getEncoded()));
		System.out.println("User PrivateKey:" + Base64.toBase64String(priKey.getEncoded()));
		System.out.println("=============测试国密CA根证书签发国密证书=============");
	}

	public static void testDigitalSign() throws Exception {
		System.out.println("=============测试国密证书数字签名=============");

		// 读取私钥
		PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(readFile("userPrivateKey"));
		KeyFactory keyFactory = KeyFactory.getInstance("EC");
		PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);

		// 读取证书
		CertificateFactory certificateFactory = CertificateFactory.getInstance("X509", "BC");
		Certificate certificate = certificateFactory.generateCertificate(new FileInputStream("userCert.cer"));

		// 签名
		String signText = "测试123456test";
		Signature signature = Signature.getInstance("SM3withSM2", "BC");
		signature.initSign(privateKey);
		signature.update(signText.getBytes(StandardCharsets.UTF_8));
		byte[] digitalSignature = signature.sign();
		System.out.println("signText:" + signText);
		System.out.println("digitalSignature:" + Base64.toBase64String(digitalSignature));

		// 验签
		Signature signature1 = Signature.getInstance("SM3withSM2", "BC");
		signature1.initVerify(certificate.getPublicKey());
		signature1.update(signText.getBytes(StandardCharsets.UTF_8));
		boolean result = signature1.verify(digitalSignature);
		System.out.println("verifyResult:" + result);

		// 验证错误的签名
		Signature signature2 = Signature.getInstance("SM3withSM2", "BC");
		signature2.initVerify(certificate.getPublicKey());
		signature2.update((signText + "exception").getBytes(StandardCharsets.UTF_8));
		boolean exceptionResult = signature2.verify(digitalSignature);
		System.out.println("exceptionVerifyResult:" + exceptionResult);

		System.out.println("=============测试国密证书数字签名=============");
	}


	public static void testSM2EcDc() throws Exception {

		System.out.println("=============测试国密SM2加解密=============");

		// 从证书获取公钥
		CertificateFactory certificateFactory = CertificateFactory.getInstance("X509", "BC");
		Certificate certificate = certificateFactory.generateCertificate(new FileInputStream("userCert.cer"));
		PublicKey publicKey = certificate.getPublicKey();

		// 获取私钥
		PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(readFile("userPrivateKey"));
		PrivateKey privateKey = KeyFactory.getInstance("EC").generatePrivate(pkcs8EncodedKeySpec);

		// 获取加密参数
		BCECPublicKey localECPublicKey = (BCECPublicKey) publicKey;
		ECParameterSpec localECParameterSpec = localECPublicKey.getParameters();
		ECDomainParameters localECDomainParameters = new ECDomainParameters(
				localECParameterSpec.getCurve(), localECParameterSpec.getG(),
				localECParameterSpec.getN());
		ECPublicKeyParameters localECPublicKeyParameters = new ECPublicKeyParameters(localECPublicKey.getQ(),
				localECDomainParameters);

		// 获取解密参数
		BCECPrivateKey sm2PriK = (BCECPrivateKey) privateKey;
		ECPrivateKeyParameters localECPrivateKeyParameters = new ECPrivateKeyParameters(
				sm2PriK.getD(), localECDomainParameters);

		// 初始化加密引擎
		SM2Engine sm2EncEngine = new SM2Engine();
		sm2EncEngine.init(true, new ParametersWithRandom(localECPublicKeyParameters));

		// 初始化解密引擎
		SM2Engine sm2DcEngine = new SM2Engine();
		sm2DcEngine.init(false, localECPrivateKeyParameters);

		// 待加密数据
		byte[] ebs = "123sssss测试".getBytes(StandardCharsets.UTF_8);
		System.out.println("原文:" + new String(ebs));

		// 加密
		byte[] bs = sm2EncEngine.processBlock(ebs, 0, ebs.length);
		String es = Base64.toBase64String(bs);
		System.out.println("密文:" + es);

		// 解密
		bs = Base64.decode(es.getBytes(StandardCharsets.UTF_8));
		byte[] b = sm2DcEngine.processBlock(bs, 0, bs.length);
		System.out.println("明文:" + new String(b));

		System.out.println("=============测试国密SM2加解密=============");
	}

	public static void saveFile(String path, byte[] data) {
		try {
			FileOutputStream fileOutputStream = new FileOutputStream(path);
			fileOutputStream.write(data);
			fileOutputStream.flush();
			fileOutputStream.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public static byte[] readFile(String path) throws Exception {
		FileInputStream fileInputStream = new FileInputStream(path);
		byte[] bytes = new byte[fileInputStream.available()];
		if (fileInputStream.read(bytes) == -1) {
			throw new Exception("文件读取失败");
		}
		return bytes;
	}
}