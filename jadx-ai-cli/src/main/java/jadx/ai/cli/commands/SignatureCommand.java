package jadx.ai.cli.commands;

import java.io.File;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import com.android.apksig.ApkVerifier;

import jadx.ai.cli.output.JsonOutput;
import jadx.api.JadxDecompiler;

@Command(name = "signature", description = "Verify APK signature and display certificate details")
public class SignatureCommand extends AbstractCommand {

    @Option(names = {"--no-verify"}, description = "Skip verification, only show certificates")
    protected boolean skipVerify;

    @Override
    protected Object execute(JadxDecompiler decompiler) throws Exception {
        File apkFile = decompiler.getArgs().getInputFiles().isEmpty()
                ? inputFile
                : decompiler.getArgs().getInputFiles().get(0);
        if (apkFile == null || !apkFile.exists()) {
            return JsonOutput.error("NoInput", "APK file not found");
        }

        Map<String, Object> result = new HashMap<>();
        result.put("file", apkFile.getName());

        if (!skipVerify) {
            ApkVerifier verifier = new ApkVerifier.Builder(apkFile).build();
            ApkVerifier.Result verifyResult = verifier.verify();

            result.put("verified", verifyResult.isVerified());
            result.put("v1Scheme", verifyResult.isVerifiedUsingV1Scheme());
            result.put("v2Scheme", verifyResult.isVerifiedUsingV2Scheme());
            result.put("v3Scheme", verifyResult.isVerifiedUsingV3Scheme());
            result.put("v31Scheme", verifyResult.isVerifiedUsingV31Scheme());

            List<Map<String, Object>> errors = new ArrayList<>();
            for (ApkVerifier.IssueWithParams err : verifyResult.getErrors()) {
                Map<String, Object> e = new HashMap<>();
                e.put("issue", err.getIssue().name());
                e.put("message", err.toString());
                errors.add(e);
            }
            result.put("errors", errors);

            List<Map<String, Object>> warnings = new ArrayList<>();
            for (ApkVerifier.IssueWithParams warn : verifyResult.getWarnings()) {
                Map<String, Object> w = new HashMap<>();
                w.put("issue", warn.getIssue().name());
                w.put("message", warn.toString());
                warnings.add(w);
            }
            result.put("warnings", warnings);

            List<Map<String, Object>> signers = new ArrayList<>();
            collectSigners(verifyResult.getV1SchemeSigners(), "V1", signers);
            collectSigners(verifyResult.getV2SchemeSigners(), "V2", signers);
            collectSigners(verifyResult.getV3SchemeSigners(), "V3", signers);
            collectSigners(verifyResult.getV31SchemeSigners(), "V3.1", signers);
            result.put("signers", signers);
        }

        return JsonOutput.ok(result);
    }

    private void collectSigners(List<? extends ApkVerifier.SignerInfo> signerInfos, String scheme, List<Map<String, Object>> signers) {
        for (ApkVerifier.SignerInfo info : signerInfos) {
            Map<String, Object> signer = new HashMap<>();
            signer.put("scheme", scheme);
            if (info.getName() != null) {
                signer.put("name", info.getName());
            }
            if (info.getIndex() >= 0) {
                signer.put("index", info.getIndex());
            }
            if (info.getCertificate() instanceof X509Certificate) {
                signer.put("certificate", extractCertInfo((X509Certificate) info.getCertificate()));
            }
            List<String> signerErrors = new ArrayList<>();
            for (ApkVerifier.IssueWithParams err : info.getErrors()) {
                signerErrors.add(err.getIssue().name() + ": " + err.toString());
            }
            if (!signerErrors.isEmpty()) {
                signer.put("errors", signerErrors);
            }
            signers.add(signer);
        }
    }

    private Map<String, Object> extractCertInfo(X509Certificate cert) {
        Map<String, Object> info = new HashMap<>();
        info.put("subject", cert.getSubjectDN().toString());
        info.put("issuer", cert.getIssuerDN().toString());
        info.put("serialNumber", cert.getSerialNumber().toString(16));
        info.put("validFrom", cert.getNotBefore().toString());
        info.put("validUntil", cert.getNotAfter().toString());
        info.put("signatureAlgorithm", cert.getSigAlgName());
        try {
            info.put("fingerprintMD5", getThumbprint(cert, "MD5"));
            info.put("fingerprintSHA1", getThumbprint(cert, "SHA-1"));
            info.put("fingerprintSHA256", getThumbprint(cert, "SHA-256"));
        } catch (Exception ignored) {
        }
        return info;
    }

    private static String getThumbprint(X509Certificate cert, String algorithm) throws Exception {
        MessageDigest md = MessageDigest.getInstance(algorithm);
        byte[] digest = md.digest(cert.getEncoded());
        StringBuilder sb = new StringBuilder();
        for (byte b : digest) {
            sb.append(String.format("%02X", b));
            sb.append(":");
        }
        if (sb.length() > 0) {
            sb.setLength(sb.length() - 1);
        }
        return sb.toString();
    }

    @Override
    protected Map<String, Object> buildDaemonArgs() {
        Map<String, Object> args = new HashMap<>();
        args.put("skipVerify", skipVerify);
        return args;
    }
}