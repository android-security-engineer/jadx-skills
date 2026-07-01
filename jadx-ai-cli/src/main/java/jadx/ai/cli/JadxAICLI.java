package jadx.ai.cli;

import picocli.CommandLine;
import picocli.CommandLine.Command;

import jadx.ai.cli.commands.DaemonCommand;
import jadx.ai.cli.commands.GraphCommand;
import jadx.ai.cli.commands.HookCommand;
import jadx.ai.cli.commands.CommentCommand;
import jadx.ai.cli.commands.McpCommand;
import jadx.ai.cli.commands.NavigateCommand;
import jadx.ai.cli.commands.ServerCommand;
import jadx.ai.cli.commands.SignatureCommand;
import jadx.ai.cli.commands.CfgCommand;
import jadx.ai.cli.commands.ClassDetailCommand;
import jadx.ai.cli.commands.DecompileCommand;
import jadx.ai.cli.commands.ExportCommand;
import jadx.ai.cli.commands.InfoCommand;
import jadx.ai.cli.commands.LineMapCommand;
import jadx.ai.cli.commands.ListCommand;
import jadx.ai.cli.commands.PackageDetailCommand;
import jadx.ai.cli.commands.ReloadCommand;
import jadx.ai.cli.commands.RenameCommand;
import jadx.ai.cli.commands.ResourcesCommand;
import jadx.ai.cli.commands.ScriptCommand;
import jadx.ai.cli.commands.SearchCommand;
import jadx.ai.cli.commands.SecretsScanCommand;
import jadx.ai.cli.commands.IocExtractCommand;
import jadx.ai.cli.commands.PermissionRiskMapCommand;
import jadx.ai.cli.commands.NativeBridgeIndexCommand;
import jadx.ai.cli.commands.CryptoScanCommand;
import jadx.ai.cli.commands.ManifestAuditCommand;
import jadx.ai.cli.commands.DeepLinkAuditCommand;
import jadx.ai.cli.commands.NetworkSecurityConfigCommand;
import jadx.ai.cli.commands.ObfuscationReportCommand;
import jadx.ai.cli.commands.NativeLibsCommand;
import jadx.ai.cli.commands.SslScanCommand;
import jadx.ai.cli.commands.WebviewScanCommand;
import jadx.ai.cli.commands.FrameworkDetectCommand;
import jadx.ai.cli.commands.StorageScanCommand;
import jadx.ai.cli.commands.IntentScanCommand;
import jadx.ai.cli.commands.SqlInjectionScanCommand;
import jadx.ai.cli.commands.CommandInjectionScanCommand;
import jadx.ai.cli.commands.LoggingScanCommand;
import jadx.ai.cli.commands.PathTraversalScanCommand;
import jadx.ai.cli.commands.SerializationScanCommand;
import jadx.ai.cli.commands.ClipboardScanCommand;
import jadx.ai.cli.commands.TamperDetectionScanCommand;
import jadx.ai.cli.commands.TapjackingScanCommand;
import jadx.ai.cli.commands.DynamicLoadingScanCommand;
import jadx.ai.cli.commands.BiometricScanCommand;
import jadx.ai.cli.commands.AccessibilityScanCommand;
import jadx.ai.cli.commands.KeystoreScanCommand;
import jadx.ai.cli.commands.ExportedProviderScanCommand;
import jadx.ai.cli.commands.NotificationListenerScanCommand;
import jadx.ai.cli.commands.SmsScanCommand;
import jadx.ai.cli.commands.PrivacyScanCommand;
import jadx.ai.cli.commands.TaskHijackingScanCommand;
import jadx.ai.cli.commands.FirebaseScanCommand;
import jadx.ai.cli.commands.XxeScanCommand;
import jadx.ai.cli.commands.IntentRedirectionScanCommand;
import jadx.ai.cli.commands.CertPinningScanCommand;
import jadx.ai.cli.commands.DebugArtifactScanCommand;
import jadx.ai.cli.commands.DeeplinkScanCommand;
import jadx.ai.cli.commands.BackupScanCommand;
import jadx.ai.cli.commands.ScreenCaptureScanCommand;
import jadx.ai.cli.commands.OtpInterceptionScanCommand;
import jadx.ai.cli.commands.PendingIntentScanCommand;
import jadx.ai.cli.commands.ContentProviderScanCommand;
import jadx.ai.cli.commands.LocalAuthBypassScanCommand;
import jadx.ai.cli.commands.UnsafeExportScanCommand;
import jadx.ai.cli.commands.InsecureKeystoreScanCommand;
import jadx.ai.cli.commands.TokenStorageScanCommand;
import jadx.ai.cli.commands.WebViewUrlScanCommand;
import jadx.ai.cli.commands.InsecureApiScanCommand;
import jadx.ai.cli.commands.NetworkTrafficScanCommand;
import jadx.ai.cli.commands.AdFraudScanCommand;
import jadx.ai.cli.commands.RuntimeIntegrityScanCommand;
import jadx.ai.cli.commands.HardcodedCryptoScanCommand;
import jadx.ai.cli.commands.PermissionRequestScanCommand;
import jadx.ai.cli.commands.DataResidueScanCommand;
import jadx.ai.cli.commands.SubprocessScanCommand;
import jadx.ai.cli.commands.CryptographicMisuseScanCommand;
import jadx.ai.cli.commands.LogInfoLeakScanCommand;
import jadx.ai.cli.commands.BroadcastScanCommand;
import jadx.ai.cli.commands.FragmentInjectionScanCommand;
import jadx.ai.cli.commands.UnsafeEncryptionScanCommand;
import jadx.ai.cli.commands.ScreenshotLeakScanCommand;
import jadx.ai.cli.commands.TrustBoundaryScanCommand;
import jadx.ai.cli.commands.InsecureDeeplinkHandlerScanCommand;
import jadx.ai.cli.commands.InsecureFileIoScanCommand;
import jadx.ai.cli.commands.SdkInventoryCommand;
import jadx.ai.cli.commands.BypassHookCommand;
import jadx.ai.cli.commands.PackerDetectCommand;
import jadx.ai.cli.commands.CapabilityReportCommand;
import jadx.ai.cli.commands.NativeLibSecurityCommand;
import jadx.ai.cli.commands.ApiEndpointExtractCommand;
import jadx.ai.cli.commands.GoogleServicesConfigCommand;
import jadx.ai.cli.commands.DangerousApiMapCommand;
import jadx.ai.cli.commands.ManifestSecurityAuditCommand;
import jadx.ai.cli.commands.Il2cppMetadataScanCommand;
import jadx.ai.cli.commands.FlutterAnalysisCommand;
import jadx.ai.cli.commands.SourceQualityReportCommand;
import jadx.ai.cli.commands.ClassInventoryCommand;
import jadx.ai.cli.commands.EntrypointScanCommand;
import jadx.ai.cli.commands.DexStatCommand;
import jadx.ai.cli.commands.CustomPermissionAuditCommand;
import jadx.ai.cli.commands.ApkSignatureCommand;
import jadx.ai.cli.commands.DeadCodeReportCommand;
import jadx.ai.cli.commands.MethodComplexityCommand;
import jadx.ai.cli.commands.ResourceInventoryCommand;
import jadx.ai.cli.commands.SharedUidAuditCommand;
import jadx.ai.cli.commands.DeviceAdminScanCommand;
import jadx.ai.cli.commands.VpnServiceScanCommand;
import jadx.ai.cli.commands.NfcScanCommand;
import jadx.ai.cli.commands.SensorScanCommand;
import jadx.ai.cli.commands.AlarmWakelockScanCommand;
import jadx.ai.cli.commands.ApktoolCommand;
import jadx.ai.cli.commands.AdbCommand;
import jadx.ai.cli.commands.FridaCommand;
import jadx.ai.cli.commands.BluetoothScanCommand;
import jadx.ai.cli.commands.AccountScanCommand;
import jadx.ai.cli.commands.LocationScanCommand;
import jadx.ai.cli.commands.SimInfoScanCommand;
import jadx.ai.cli.commands.SmaliCommand;
import jadx.ai.cli.commands.FindClassesCommand;
import jadx.ai.cli.commands.StringXrefCommand;
import jadx.ai.cli.commands.CallSitesCommand;
import jadx.ai.cli.commands.IndexCommand;
import jadx.ai.cli.commands.UsageCommand;

@Command(
		name = "jadx-ai",
		description = "AI-friendly CLI for JADX decompiler - structured JSON output",
		subcommands = {
				ClassDetailCommand.class,
				DecompileCommand.class,
				SearchCommand.class,
				IndexCommand.class,
				UsageCommand.class,
				ListCommand.class,
				ExportCommand.class,
				InfoCommand.class,
				ResourcesCommand.class,
				ScriptCommand.class,
				PackageDetailCommand.class,
				LineMapCommand.class,
				RenameCommand.class,
				ReloadCommand.class,
					DaemonCommand.class,
				GraphCommand.class,
				HookCommand.class,
				NavigateCommand.class,
				CommentCommand.class,
					CfgCommand.class,
					SignatureCommand.class,
					SecretsScanCommand.class,
					IocExtractCommand.class,
					PermissionRiskMapCommand.class,
					NativeBridgeIndexCommand.class,
					CryptoScanCommand.class,
					ManifestAuditCommand.class,
					DeepLinkAuditCommand.class,
					NetworkSecurityConfigCommand.class,
					ObfuscationReportCommand.class,
					NativeLibsCommand.class,
					SslScanCommand.class,
					WebviewScanCommand.class,
					FrameworkDetectCommand.class,
					StorageScanCommand.class,
					IntentScanCommand.class,
					SqlInjectionScanCommand.class,
					CommandInjectionScanCommand.class,
					LoggingScanCommand.class,
					PathTraversalScanCommand.class,
					SerializationScanCommand.class,
					ClipboardScanCommand.class,
					TamperDetectionScanCommand.class,
					TapjackingScanCommand.class,
					DynamicLoadingScanCommand.class,
					BiometricScanCommand.class,
					AccessibilityScanCommand.class,
					KeystoreScanCommand.class,
					ExportedProviderScanCommand.class,
					NotificationListenerScanCommand.class,
					SmsScanCommand.class,
					PrivacyScanCommand.class,
					TaskHijackingScanCommand.class,
					FirebaseScanCommand.class,
					XxeScanCommand.class,
					IntentRedirectionScanCommand.class,
					CertPinningScanCommand.class,
					DebugArtifactScanCommand.class,
					DeeplinkScanCommand.class,
					BackupScanCommand.class,
					ScreenCaptureScanCommand.class,
					OtpInterceptionScanCommand.class,
					PendingIntentScanCommand.class,
					ContentProviderScanCommand.class,
					LocalAuthBypassScanCommand.class,
					UnsafeExportScanCommand.class,
					InsecureKeystoreScanCommand.class,
					TokenStorageScanCommand.class,
					WebViewUrlScanCommand.class,
					InsecureApiScanCommand.class,
					NetworkTrafficScanCommand.class,
					AdFraudScanCommand.class,
					RuntimeIntegrityScanCommand.class,
					HardcodedCryptoScanCommand.class,
					PermissionRequestScanCommand.class,
					DataResidueScanCommand.class,
					SubprocessScanCommand.class,
					CryptographicMisuseScanCommand.class,
					LogInfoLeakScanCommand.class,
					BroadcastScanCommand.class,
					FragmentInjectionScanCommand.class,
					UnsafeEncryptionScanCommand.class,
					ScreenshotLeakScanCommand.class,
					TrustBoundaryScanCommand.class,
					InsecureDeeplinkHandlerScanCommand.class,
					InsecureFileIoScanCommand.class,
					SdkInventoryCommand.class,
					BypassHookCommand.class,
					PackerDetectCommand.class,
					CapabilityReportCommand.class,
					NativeLibSecurityCommand.class,
					ApiEndpointExtractCommand.class,
					GoogleServicesConfigCommand.class,
					DangerousApiMapCommand.class,
					ManifestSecurityAuditCommand.class,
					Il2cppMetadataScanCommand.class,
					FlutterAnalysisCommand.class,
					SourceQualityReportCommand.class,
					ClassInventoryCommand.class,
					EntrypointScanCommand.class,
					DexStatCommand.class,
					CustomPermissionAuditCommand.class,
					ApkSignatureCommand.class,
					DeadCodeReportCommand.class,
					MethodComplexityCommand.class,
					ResourceInventoryCommand.class,
					SharedUidAuditCommand.class,
					DeviceAdminScanCommand.class,
					VpnServiceScanCommand.class,
					NfcScanCommand.class,
					SensorScanCommand.class,
					AlarmWakelockScanCommand.class,
					ApktoolCommand.class,
					AdbCommand.class,
						BluetoothScanCommand.class,
					AccountScanCommand.class,
					LocationScanCommand.class,
					SmaliCommand.class,
					FindClassesCommand.class,
					StringXrefCommand.class,
					CallSitesCommand.class,
					SimInfoScanCommand.class,
					FridaCommand.class,
					McpCommand.class,
					ServerCommand.class
		},
		mixinStandardHelpOptions = true,
		version = "1.0.0"
)
public class JadxAICLI implements Runnable {
	@Override
	public void run() {
		CommandLine.usage(this, System.out);
	}

	public static void main(String[] args) {
		int exitCode = new CommandLine(new JadxAICLI()).execute(args);
		System.exit(exitCode);
	}
}
