plugins {
	id("jadx-library")
	application
	id("com.gradleup.shadow") version "8.3.8"
}

application {
	mainClass.set("jadx.ai.cli.JadxAICLI")
	applicationName = "jadx-ai"
	applicationDefaultJvmArgs =
		listOf(
			"-Xms256M",
			"-XX:MaxRAMPercentage=70.0",
		)
}

dependencies {
	implementation(project(":jadx-core"))

	implementation("info.picocli:picocli:4.7.5")
		implementation("com.android.tools.build:apksig:8.13.1")
	implementation("com.google.code.gson:gson:2.10.1")
	implementation("org.slf4j:slf4j-api:2.0.9")
	runtimeOnly("ch.qos.logback:logback-classic:1.4.11")

	// Input plugins — without these, jadx loads 0 classes from .dex/.apk/etc.
	// Mirrors jadx-cli so every supported container format is parseable.
	runtimeOnly(project(":jadx-plugins:jadx-dex-input"))
	runtimeOnly(project(":jadx-plugins:jadx-java-input"))
	runtimeOnly(project(":jadx-plugins:jadx-java-convert"))
	runtimeOnly(project(":jadx-plugins:jadx-smali-input"))
	runtimeOnly(project(":jadx-plugins:jadx-rename-mappings"))
	runtimeOnly(project(":jadx-plugins:jadx-kotlin-metadata"))
	runtimeOnly(project(":jadx-plugins:jadx-kotlin-source-debug-extension"))
	runtimeOnly(project(":jadx-plugins:jadx-xapk-input"))
	runtimeOnly(project(":jadx-plugins:jadx-aab-input"))
	runtimeOnly(project(":jadx-plugins:jadx-apkm-input"))
	runtimeOnly(project(":jadx-plugins:jadx-apks-input"))

	testImplementation("org.junit.jupiter:junit-jupiter:5.10.1")
}

tasks.test {
	useJUnitPlatform()
}

tasks.jar {
	manifest {
		attributes("Main-Class" to "jadx.ai.cli.JadxAICLI")
	}
}

tasks.shadowJar {
	mergeServiceFiles()
	manifest {
		attributes("Main-Class" to "jadx.ai.cli.JadxAICLI")
	}
}
